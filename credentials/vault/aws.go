// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awscreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	"github.com/hashicorp/go-hclog"
	awsutil "github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
	"github.com/hashicorp/vault-secrets-operator/helpers"
)

// stsNativeResolver is the AWS SDK v2 default endpoint resolver for STS,
// used to derive the correct regional endpoint without hardcoding URL patterns.
var stsNativeResolver = sts.NewDefaultEndpointResolverV2()

const (
	iamServerIDHeader        = "X-Vault-AWS-IAM-Server-ID"
	stsGetCallerIdentityBody = "Action=GetCallerIdentity&Version=2011-06-15"
	stsContentType           = "application/x-www-form-urlencoded; charset=utf-8"
	stsSigningName           = "sts"
)

// customSTSEndpointResolver implements sts.EndpointResolverV2 for a fixed endpoint URL.
type customSTSEndpointResolver struct {
	endpointURL string
}

func (r *customSTSEndpointResolver) ResolveEndpoint(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	uri, err := url.Parse(r.endpointURL)
	if err != nil {
		return smithyendpoints.Endpoint{}, fmt.Errorf("failed to parse custom STS endpoint URL: %w", err)
	}
	return smithyendpoints.Endpoint{URI: *uri}, nil
}

// customIAMEndpointResolver implements iam.EndpointResolverV2 for a fixed endpoint URL.
type customIAMEndpointResolver struct {
	endpointURL string
}

func (r *customIAMEndpointResolver) ResolveEndpoint(_ context.Context, _ iam.EndpointParameters) (smithyendpoints.Endpoint, error) {
	uri, err := url.Parse(r.endpointURL)
	if err != nil {
		return smithyendpoints.Endpoint{}, fmt.Errorf("failed to parse custom IAM endpoint URL: %w", err)
	}
	return smithyendpoints.Endpoint{URI: *uri}, nil
}

type stsSigningEndpoint struct {
	requestURL    string
	signingName   string
	signingRegion string
}

// generateLoginData builds the Vault AWS IAM login payload by constructing and
// signing a sts:GetCallerIdentity HTTP request using AWS SDK v2.
// It replicates the behaviour of the now-removed awsutil.GenerateLoginData from
// go-secure-stdlib/awsutil v0.
func generateLoginData(ctx context.Context, awsConfig *aws.Config, headerValue, stsEndpoint string) (map[string]interface{}, error) {
	if awsConfig == nil || awsConfig.Credentials == nil {
		return nil, fmt.Errorf("AWS credentials are not configured")
	}

	credentials, err := awsConfig.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AWS credentials: %w", err)
	}
	if !credentials.HasKeys() {
		return nil, fmt.Errorf("retrieved AWS credentials are empty")
	}

	region := awsConfig.Region
	if region == "" {
		region = awsutil.DefaultRegion
	}

	endpoint, err := resolveSTSSigningEndpoint(ctx, region, stsEndpoint)
	if err != nil {
		return nil, err
	}

	req, body, err := buildSignedGetCallerIdentityRequest(ctx, credentials, endpoint, headerValue)
	if err != nil {
		return nil, err
	}

	headers := req.Header.Clone()
	if headers.Get("Host") == "" {
		headers.Set("Host", req.URL.Host)
	}

	headersJSON, err := json.Marshal(headers)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request headers: %w", err)
	}

	loginData := map[string]interface{}{
		"iam_http_request_method": req.Method,
		"iam_request_url":         base64.StdEncoding.EncodeToString([]byte(req.URL.String())),
		"iam_request_headers":     base64.StdEncoding.EncodeToString(headersJSON),
		"iam_request_body":        base64.StdEncoding.EncodeToString([]byte(body)),
	}
	return loginData, nil
}

// resolveSTSSigningEndpoint returns the STS URL and signing metadata for the given region.
// When a custom endpoint is provided it is used directly; otherwise the AWS SDK
// v2 default endpoint resolver is used to derive the correct regional endpoint,
// which correctly handles non-standard partitions (GovCloud, China, etc.).
func resolveSTSSigningEndpoint(ctx context.Context, region, endpointURL string) (stsSigningEndpoint, error) {
	if endpointURL != "" {
		uri, err := url.Parse(endpointURL)
		if err != nil {
			return stsSigningEndpoint{}, fmt.Errorf("failed to parse custom STS endpoint URL: %w", err)
		}
		if uri.Scheme == "" || uri.Host == "" {
			return stsSigningEndpoint{}, fmt.Errorf("invalid custom STS endpoint URL %q", endpointURL)
		}
		return stsSigningEndpoint{
			requestURL:    uri.String(),
			signingName:   stsSigningName,
			signingRegion: region,
		}, nil
	}
	// Use the SDK v2 native resolver so that partition-specific DNS suffixes
	// (e.g. amazonaws.com.cn for cn-*, us-gov-*.amazonaws.com for GovCloud)
	// are derived correctly rather than hardcoded.
	resolved, err := stsNativeResolver.ResolveEndpoint(ctx, sts.EndpointParameters{
		Region: aws.String(region),
	})
	if err != nil {
		return stsSigningEndpoint{}, fmt.Errorf("failed to resolve STS endpoint for region %q: %w", region, err)
	}
	return stsSigningEndpoint{
		requestURL:    resolved.URI.String(),
		signingName:   stsSigningName,
		signingRegion: region,
	}, nil
}

func buildSignedGetCallerIdentityRequest(ctx context.Context, credentials aws.Credentials, endpoint stsSigningEndpoint, headerValue string) (*http.Request, string, error) {
	body := stsGetCallerIdentityBody
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.requestURL, strings.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to build GetCallerIdentity request: %w", err)
	}

	req.Header.Set("Content-Type", stsContentType)
	if headerValue != "" {
		req.Header.Set(iamServerIDHeader, headerValue)
	}

	// resolveSTSSigningEndpoint and generateLoginData guarantee non-empty
	// signingRegion and signingName before reaching here.
	payloadHash := sha256.Sum256([]byte(body))
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, credentials, req, hex.EncodeToString(payloadHash[:]), endpoint.signingName, endpoint.signingRegion, time.Now().UTC()); err != nil {
		return nil, "", fmt.Errorf("failed to sign GetCallerIdentity request: %w", err)
	}

	return req, body, nil
}

const (
	AWSAnnotationRole            = "eks.amazonaws.com/role-arn"
	AWSAnnotationAudience        = "eks.amazonaws.com/audience"
	AWSAnnotationTokenExpiration = "eks.amazonaws.com/token-expiration"
	AWSDefaultAudience           = "sts.amazonaws.com"
	AWSDefaultTokenExpiration    = int64(86400)
	K8sRootCA                    = "kube-root-ca.crt"
)

// Compile-time assertion that AWSCredentialProvider implements CredentialProvider.
var _ CredentialProvider = (*AWSCredentialProvider)(nil)

type AWSCredentialProvider struct {
	authObj           *secretsv1beta1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *AWSCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *AWSCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *AWSCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) error {
	if authObj.Spec.AWS == nil {
		return fmt.Errorf("AWS auth method not configured")
	}
	if err := authObj.Spec.AWS.Validate(); err != nil {
		return fmt.Errorf("invalid AWS auth configuration: %w", err)
	}

	l.authObj = authObj
	l.providerNamespace = providerNamespace

	if l.authObj.Spec.AWS.SecretRef != "" {
		// If SecretRef is not empty, get the secret and read the creds from
		// there, use the secret UID as l.uid
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.SecretRef,
		}
		credsSecret, err := helpers.GetSecret(ctx, client, key)
		if err != nil {
			return err
		}
		l.uid = credsSecret.UID
	} else if l.authObj.Spec.AWS.IRSAServiceAccount != "" {
		// Otherwise if the IRSA ref is not empty, read the service account, and
		// use the service account UID as l.uid
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.IRSAServiceAccount,
		}
		irsaServiceAccount, err := helpers.GetServiceAccount(ctx, client, key)
		if err != nil {
			return err
		}
		l.uid = irsaServiceAccount.UID
	} else {
		// At this point either the node role or the instance profile will be
		// used for credentials, and since those are cluster-wide entities, just
		// use the root CA UID
		key := ctrlclient.ObjectKey{
			Namespace: common.OperatorNamespace,
			Name:      K8sRootCA,
		}
		kubeRootCA, err := helpers.GetConfigMap(ctx, client, key)
		if err != nil {
			return err
		}
		l.uid = kubeRootCA.UID
	}

	return nil
}

func (l *AWSCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)
	credsSecret := &corev1.Secret{}
	irsaToken := ""
	var irsaConfig *IRSAConfig

	if l.authObj.Spec.AWS.SecretRef != "" {
		var err error
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.SecretRef,
		}
		credsSecret, err = helpers.GetSecret(ctx, client, key)
		if err != nil {
			logger.Error(err, "Failed to get secret", "secret_name", l.authObj.Spec.AWS.SecretRef)
			return nil, err
		}
	} else if l.authObj.Spec.AWS.IRSAServiceAccount != "" {
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.IRSAServiceAccount,
		}
		irsaServiceAccount, err := helpers.GetServiceAccount(ctx, client, key)
		if err != nil {
			logger.Error(err, "Failed to get IRSA service account", "service_account", l.authObj.Spec.AWS.IRSAServiceAccount)
			return nil, err
		}
		irsaConfig, err = getIRSAConfig(irsaServiceAccount.Annotations)
		if err != nil {
			return nil, err
		}

		token, err := helpers.RequestSAToken(ctx, client, irsaServiceAccount, irsaConfig.TokenExpiration, []string{irsaConfig.Audience})
		if err != nil {
			logger.Error(err, "Failed to get service account token")
			return nil, err
		}
		irsaToken = token.Status.Token
	}

	config, err := l.getCredentialsConfig(credsSecret, irsaConfig, irsaToken)
	if err != nil {
		return nil, err
	}

	config.Logger = hclog.Default()
	config.Logger.SetLevel(hclog.Debug)

	// The awsutil v0 option WithSkipWebIdentityValidity(true) has no v2
	// equivalent: the SDK v2 WebIdentityRoleProvider reads the token lazily at
	// signing time, so there is no upfront validity window to bypass.
	awsCfg, err := config.GenerateCredentialChain(ctx, credentialChainOptions()...)
	if err != nil {
		return nil, err
	}
	applyCredentialsOverride(awsCfg, config, irsaConfig, irsaToken)

	headerValue := l.authObj.Spec.AWS.HeaderValue

	loginData, err := generateLoginData(ctx, awsCfg, headerValue, l.authObj.Spec.AWS.STSEndpoint)
	if err != nil {
		return nil, err
	}
	loginData["role"] = l.authObj.Spec.AWS.Role
	return loginData, nil
}

func (l *AWSCredentialProvider) getCredentialsConfig(credsSecret *corev1.Secret, irsaConfig *IRSAConfig, token string) (*awsutil.CredentialsConfig, error) {
	config, err := awsutil.NewCredentialsConfig()
	if err != nil {
		return nil, err
	}

	if l.authObj.Spec.AWS.Region != "" {
		config.Region = l.authObj.Spec.AWS.Region
	}
	if l.authObj.Spec.AWS.SessionName != "" {
		config.RoleSessionName = l.authObj.Spec.AWS.SessionName
	}
	if l.authObj.Spec.AWS.STSEndpoint != "" {
		config.STSEndpointResolver = &customSTSEndpointResolver{endpointURL: l.authObj.Spec.AWS.STSEndpoint}
	}
	if l.authObj.Spec.AWS.IAMEndpoint != "" {
		config.IAMEndpointResolver = &customIAMEndpointResolver{endpointURL: l.authObj.Spec.AWS.IAMEndpoint}
	}

	// awsutil passes Filename to config.WithSharedCredentialsFiles
	// unconditionally, so an empty value replaces the SDK's normal lookup with
	// an empty path and shared-credentials auth fails outright. Resolve the
	// path the way the SDK would.
	if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
		config.Filename = f
	} else {
		config.Filename = awsconfig.DefaultSharedCredentialsFilename()
	}

	if credsSecret != nil {
		if v, ok := credsSecret.Data[consts.AWSAccessKeyID]; ok {
			config.AccessKey = string(v)
		}
		if v, ok := credsSecret.Data[consts.AWSSecretAccessKey]; ok {
			config.SecretKey = string(v)
		}
		if v, ok := credsSecret.Data[consts.AWSSessionToken]; ok {
			config.SessionToken = string(v)
		}
	}

	if irsaConfig != nil {
		config.RoleARN = irsaConfig.RoleARN
	}

	if token != "" {
		config.WebIdentityToken = token
	}

	return config, nil
}

// credentialChainOptions returns the awsutil options for
// GenerateCredentialChain.
//
// Environment credentials must outrank a shared profile, as they do in the AWS
// credential chain. awsutil selects a shared profile whenever one exists, and
// aws-sdk-go-v2 checks for a selected profile before it checks for environment
// credentials, so leaving shared credentials enabled would let a stray
// ~/.aws/credentials silently take over. Disabling them when environment
// credentials are present restores the expected order.
func credentialChainOptions() []awsutil.Option {
	if envStaticCredentialsSet() {
		return []awsutil.Option{awsutil.WithSharedCredentials(false)}
	}
	return nil
}

// envStaticCredentialsSet reports whether the environment carries a complete
// static credential pair, using the same variables and precedence as the SDK.
func envStaticCredentialsSet() bool {
	keyID := os.Getenv("AWS_ACCESS_KEY_ID")
	if keyID == "" {
		keyID = os.Getenv("AWS_ACCESS_KEY")
	}
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	if secret == "" {
		secret = os.Getenv("AWS_SECRET_KEY")
	}
	return keyID != "" && secret != ""
}

// applyCredentialsOverride replaces awsCfg.Credentials with a role-assumption
// provider built from credsConfig, using an STS client that honors a custom
// STSEndpointResolver. It serves the IRSA flow (RoleARN plus a web identity
// token) and the node-role flow (RoleARN alone, sourcing its credentials from
// the chain, typically EC2 IMDS).
//
// It exists because GenerateCredentialChain builds neither provider for the way
// VSO supplies its inputs, and never propagates STSEndpointResolver into them.
//
// Two constraints are load-bearing:
//
//   - A RoleARN alone is not a request to assume it. awsutil seeds
//     CredentialsConfig.RoleARN from the operator pod's own AWS_ROLE_ARN, set
//     whenever VSO itself runs under IRSA, so this stands down when the chain
//     already resolved static credentials - they outrank role assumption, and
//     acting on an inherited role would authenticate as the operator rather
//     than the configured identity. An irsaServiceAccount on the VaultAuth is
//     an explicit request and still wins.
//   - The provider resolves lazily, so a failed role assumption surfaces as an
//     error from GetCreds. awsutil v0 logged a warning and continued with the
//     unassumed credentials; failing loudly is deliberate, since a silent
//     fallback would authenticate under an unexpected identity.
func applyCredentialsOverride(awsCfg *aws.Config, credsConfig *awsutil.CredentialsConfig, irsaConfig *IRSAConfig, irsaToken string) {
	// An irsaServiceAccount on the VaultAuth is an explicit request to assume
	// that role using a freshly requested ServiceAccount token, so it outranks
	// whatever the ambient credential chain resolved.
	explicitIRSA := irsaConfig != nil && irsaConfig.RoleARN != "" && irsaToken != ""

	// Assume the role that was actually validated above. credsConfig.RoleARN
	// holds the same value on the IRSA path today, but it is also the field
	// awsutil seeds from the operator pod's own AWS_ROLE_ARN, so keying off the
	// validated value keeps the decision and the action on the same input.
	roleARN := credsConfig.RoleARN
	if explicitIRSA {
		roleARN = irsaConfig.RoleARN
	}
	if roleARN == "" {
		return
	}

	// Outside the explicit IRSA case the role may have been inherited from the
	// operator pod's environment. Defer to the chain when it selected static
	// credentials, which outrank role assumption.
	if !explicitIRSA && resolvedStaticCredentials(awsCfg.Credentials) {
		return
	}

	var stsOpts []func(*sts.Options)
	if credsConfig.STSEndpointResolver != nil {
		stsOpts = append(stsOpts, sts.WithEndpointResolverV2(credsConfig.STSEndpointResolver))
	}
	// Built before awsCfg.Credentials is replaced below, so that the
	// assume-role flow signs its sts:AssumeRole call with the credentials the
	// chain already resolved (e.g. the EC2 instance profile).
	stsClient := sts.NewFromConfig(*awsCfg, stsOpts...)

	var tokenRetriever stscreds.IdentityTokenRetriever
	switch {
	case explicitIRSA:
		// Use the VaultAuth's ServiceAccount token rather than any token file
		// the operator pod happens to have mounted for its own identity.
		tokenRetriever = awsutil.FetchTokenContents(irsaToken)
	case credsConfig.WebIdentityTokenFile != "":
		tokenRetriever = stscreds.IdentityTokenFile(credsConfig.WebIdentityTokenFile)
	case credsConfig.WebIdentityToken != "":
		tokenRetriever = awsutil.FetchTokenContents(credsConfig.WebIdentityToken)
	}

	var provider aws.CredentialsProvider
	if tokenRetriever != nil {
		provider = stscreds.NewWebIdentityRoleProvider(stsClient, roleARN, tokenRetriever,
			func(o *stscreds.WebIdentityRoleOptions) {
				if credsConfig.RoleSessionName != "" {
					o.RoleSessionName = credsConfig.RoleSessionName
				}
			})
	} else {
		provider = stscreds.NewAssumeRoleProvider(stsClient, roleARN,
			func(o *stscreds.AssumeRoleOptions) {
				if credsConfig.RoleSessionName != "" {
					o.RoleSessionName = credsConfig.RoleSessionName
				}
				if credsConfig.RoleExternalId != "" {
					o.ExternalID = aws.String(credsConfig.RoleExternalId)
				}
				// Sorted for a deterministic request shape.
				for _, k := range sortedKeys(credsConfig.RoleTags) {
					o.Tags = append(o.Tags, ststypes.Tag{
						Key:   aws.String(k),
						Value: aws.String(credsConfig.RoleTags[k]),
					})
				}
			})
	}

	awsCfg.Credentials = aws.NewCredentialsCache(provider)
}

// resolvedStaticCredentials reports whether the credential chain settled on
// static credentials. These come from secretRef, the environment, or a shared
// profile, and all of them outrank role assumption in the AWS credential
// chain. The check is a type inspection, so it does not trigger credential
// retrieval.
func resolvedStaticCredentials(provider aws.CredentialsProvider) bool {
	return aws.IsCredentialsProvider(provider, awscreds.StaticCredentialsProvider{})
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// IRSAConfig - supported annotations on an IRSA-enabled service account
type IRSAConfig struct {
	// eks.amazonaws.com/role-arn
	RoleARN string
	// eks.amazonaws.com/audience
	Audience string
	// eks.amazonaws.com/token-expiration
	TokenExpiration int64
}

func getIRSAConfig(annotations map[string]string) (*IRSAConfig, error) {
	// Set defaults
	config := &IRSAConfig{
		Audience:        AWSDefaultAudience,
		TokenExpiration: AWSDefaultTokenExpiration,
	}

	// Set the role arn (required)
	if v, ok := annotations[AWSAnnotationRole]; ok {
		config.RoleARN = v
	} else {
		return nil, fmt.Errorf("missing %q annotation", AWSAnnotationRole)
	}

	// Override defaults from any other annotations set
	if v, ok := annotations[AWSAnnotationAudience]; ok {
		config.Audience = v
	}
	if v, ok := annotations[AWSAnnotationTokenExpiration]; ok {
		check, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse annotation %q: %q as int: %w",
				AWSAnnotationTokenExpiration, annotations[AWSAnnotationTokenExpiration], err)
		}
		config.TokenExpiration = check
	}

	return config, nil
}
