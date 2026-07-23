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
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

	region := awsConfig.Region
	if region == "" {
		region = awsutil.DefaultRegion
	}

	endpoint, err := resolveSTSSigningEndpoint(region, stsEndpoint)
	if err != nil {
		return nil, err
	}

	req, body, err := buildSignedGetCallerIdentityRequest(ctx, credentials, endpoint, region, headerValue)
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
// When a custom endpoint is provided it is used directly; otherwise a regional
// endpoint of the form https://sts.<region>.amazonaws.com is used, ensuring
// the signed Host header always matches the target region.
func resolveSTSSigningEndpoint(region, endpointURL string) (stsSigningEndpoint, error) {
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
	return stsSigningEndpoint{
		requestURL:    fmt.Sprintf("https://sts.%s.amazonaws.com", region),
		signingName:   stsSigningName,
		signingRegion: region,
	}, nil
}

func buildSignedGetCallerIdentityRequest(ctx context.Context, credentials aws.Credentials, endpoint stsSigningEndpoint, region, headerValue string) (*http.Request, string, error) {
	body := stsGetCallerIdentityBody
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.requestURL, strings.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("failed to build GetCallerIdentity request: %w", err)
	}

	req.Header.Set("Content-Type", stsContentType)
	if headerValue != "" {
		req.Header.Set(iamServerIDHeader, headerValue)
	}

	signingRegion := endpoint.signingRegion
	if signingRegion == "" {
		signingRegion = region
	}
	if signingRegion == "" {
		signingRegion = awsutil.DefaultRegion
	}
	signingName := endpoint.signingName
	if signingName == "" {
		signingName = stsSigningName
	}

	payloadHash := sha256.Sum256([]byte(body))
	signer := v4.NewSigner()
	if err := signer.SignHTTP(ctx, credentials, req, hex.EncodeToString(payloadHash[:]), signingName, signingRegion, time.Now().UTC()); err != nil {
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

	// GenerateCredentialChain returns *aws.Config (SDK v2).
	awsCfg, err := config.GenerateCredentialChain(ctx)
	if err != nil {
		return nil, err
	}

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
