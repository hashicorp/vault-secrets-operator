// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyendpoints "github.com/aws/smithy-go/endpoints"
	awsutil "github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/common"
	"github.com/hashicorp/vault-secrets-operator/consts"
)

func Test_getIRSAConfig(t *testing.T) {
	tests := map[string]struct {
		annotations    map[string]string
		expectedConfig *IRSAConfig
		expectedErr    string
	}{
		"all options": {
			annotations: map[string]string{
				AWSAnnotationAudience:        "www.this.www.that",
				AWSAnnotationRole:            "testrole",
				AWSAnnotationTokenExpiration: "600",
			},
			expectedConfig: &IRSAConfig{
				RoleARN:         "testrole",
				Audience:        "www.this.www.that",
				TokenExpiration: 600,
			},
		},
		"defaults and role": {
			annotations: map[string]string{
				AWSAnnotationRole: "testrole",
			},
			expectedConfig: &IRSAConfig{
				RoleARN:         "testrole",
				Audience:        AWSDefaultAudience,
				TokenExpiration: AWSDefaultTokenExpiration,
			},
		},
		"missing role-arn": {
			annotations: map[string]string{
				AWSAnnotationAudience: "test.aud",
			},
			expectedErr: fmt.Sprintf("missing %q annotation", AWSAnnotationRole),
		},
		"malformed expiration": {
			annotations: map[string]string{
				AWSAnnotationRole:            "testrole",
				AWSAnnotationTokenExpiration: "not-a-number",
			},
			expectedErr: fmt.Sprintf("failed to parse annotation %q: %q as int: %s",
				AWSAnnotationTokenExpiration, "not-a-number",
				`strconv.ParseInt: parsing "not-a-number": invalid syntax`),
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			config, err := getIRSAConfig(tc.annotations)
			if tc.expectedErr != "" {
				assert.EqualError(t, err, tc.expectedErr)
			} else {
				assert.Equal(t, tc.expectedConfig, config)
			}
		})
	}
}

func Test_resolveSTSSigningEndpoint(t *testing.T) {
	tests := map[string]struct {
		region      string
		endpointURL string
		wantURL     string
		wantRegion  string
		wantErr     string
	}{
		"default region no custom endpoint": {
			region:     "us-east-1",
			wantURL:    "https://sts.us-east-1.amazonaws.com",
			wantRegion: "us-east-1",
		},
		"non-default region no custom endpoint": {
			region:     "eu-west-1",
			wantURL:    "https://sts.eu-west-1.amazonaws.com",
			wantRegion: "eu-west-1",
		},
		"custom endpoint overrides region URL": {
			region:      "us-east-1",
			endpointURL: "https://custom-sts.example.com",
			wantURL:     "https://custom-sts.example.com",
			wantRegion:  "us-east-1",
		},
		"custom endpoint with path": {
			region:      "us-west-2",
			endpointURL: "https://localstack:4566/",
			wantURL:     "https://localstack:4566/",
			wantRegion:  "us-west-2",
		},
		"invalid custom endpoint - no scheme": {
			region:      "us-east-1",
			endpointURL: "localstack:4566",
			wantErr:     `invalid custom STS endpoint URL "localstack:4566"`,
		},
		"invalid custom endpoint - no host": {
			region:      "us-east-1",
			endpointURL: "https://",
			wantErr:     `invalid custom STS endpoint URL "https://"`,
		},
		"malformed URL": {
			region:      "us-east-1",
			endpointURL: "://bad",
			wantErr:     `failed to parse custom STS endpoint URL`,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ep, err := resolveSTSSigningEndpoint(context.Background(), tc.region, tc.endpointURL)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantURL, ep.requestURL)
			assert.Equal(t, tc.wantRegion, ep.signingRegion)
			assert.Equal(t, stsSigningName, ep.signingName)
		})
	}
}

// staticCredentialsProvider is a minimal aws.CredentialsProvider for tests that
// returns a fixed set of credentials without making any network calls.
type staticCredentialsProvider struct {
	creds aws.Credentials
}

func (s staticCredentialsProvider) Retrieve(_ context.Context) (aws.Credentials, error) {
	return s.creds, nil
}

const assumeRoleWithWebIdentityResponse = `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAIRSAONLY</AccessKeyId>
      <SecretAccessKey>irsa-secret</SecretAccessKey>
      <SessionToken>irsa-session-token</SessionToken>
      <Expiration>2999-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`

// isolateAWSEnvironment clears every ambient AWS credential source so a test
// exercises only what the VaultAuth spec supplies. Shared config/credentials
// files are pointed at nonexistent paths, and the static, web-identity and
// container credential environment variables are blanked (the SDK treats an
// empty value as unset).
func isolateAWSEnvironment(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "nonexistent-credentials"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "nonexistent-config"))
	for _, key := range []string{
		"AWS_PROFILE",
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"AWS_WEB_IDENTITY_TOKEN_FILE",
		"AWS_ROLE_ARN",
		"AWS_ROLE_SESSION_NAME",
		"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
		"AWS_CONTAINER_CREDENTIALS_FULL_URI",
	} {
		t.Setenv(key, "")
	}
}

// ─── shared test helpers ───
//
// These cover the three pieces of setup that nearly every AWS auth test needs:
// a fake Kubernetes client, a fake STS endpoint that records the calls VSO
// makes, and decoding of the Vault login payload.

// stsRecorder is a fake AWS STS endpoint. It records the form-encoded body of
// every request it receives so tests can assert on the exact API call VSO made
// - which action, which role, which token - rather than only on the outcome.
type stsRecorder struct {
	// URL is the endpoint to hand to spec.aws.stsEndpoint or an
	// STSEndpointResolver.
	URL string

	mu    sync.Mutex
	calls []url.Values
}

// Calls returns a copy of the recorded requests, safe to read from the test
// goroutine while the server is still running.
func (s *stsRecorder) Calls() []url.Values {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]url.Values(nil), s.calls...)
}

// Resolver returns an sts.EndpointResolverV2 pointing at this server, for the
// unit-level tests that configure a CredentialsConfig directly rather than
// going through spec.aws.stsEndpoint.
func (s *stsRecorder) Resolver(t *testing.T) sts.EndpointResolverV2 {
	t.Helper()
	u, err := url.Parse(s.URL)
	require.NoError(t, err)
	return stsEndpointResolverFunc(func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
		return smithyendpoints.Endpoint{URI: *u}, nil
	})
}

// newSTSRecorder starts a fake STS endpoint that answers every request with the
// given status and body. The server is closed when the test finishes.
func newSTSRecorder(t *testing.T, status int, body string) *stsRecorder {
	t.Helper()

	rec := &stsRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rec.mu.Lock()
		rec.calls = append(rec.calls, r.PostForm)
		rec.mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	rec.URL = srv.URL
	return rec
}

// newFakeClient builds a controller-runtime fake client with the schemes VSO
// needs, seeded with the given objects.
func newFakeClient(t *testing.T, objs ...ctrlclient.Object) *fake.ClientBuilder {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objs...)
}

// newIRSAServiceAccount builds an IRSA-annotated ServiceAccount. Passing nil
// annotations yields just the required role-arn annotation.
func newIRSAServiceAccount(name, namespace, roleARN string, annotations map[string]string) *corev1.ServiceAccount {
	if annotations == nil {
		annotations = map[string]string{AWSAnnotationRole: roleARN}
	}
	return &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   namespace,
			UID:         "sa-uid",
			Annotations: annotations,
		},
	}
}

// withTokenRequests makes the fake client's TokenRequest subresource mint the
// supplied token, and records every TokenRequest spec VSO asked for so tests
// can assert on the requested audience and expiration.
func withTokenRequests(b *fake.ClientBuilder, token string, recorded *[]authenticationv1.TokenRequestSpec, mu *sync.Mutex) *fake.ClientBuilder {
	return b.WithInterceptorFuncs(interceptor.Funcs{
		SubResourceCreate: func(ctx context.Context, c ctrlclient.Client, subResourceName string, obj, subResource ctrlclient.Object, opts ...ctrlclient.SubResourceCreateOption) error {
			tr, ok := subResource.(*authenticationv1.TokenRequest)
			if !ok || subResourceName != "token" {
				return c.SubResource(subResourceName).Create(ctx, obj, subResource, opts...)
			}
			if recorded != nil {
				mu.Lock()
				*recorded = append(*recorded, tr.Spec)
				mu.Unlock()
			}
			tr.Status.Token = token
			return nil
		},
	})
}

// kubeRootCAConfigMap is the ConfigMap Init falls back to for its cache
// identity when neither secretRef nor irsaServiceAccount is configured.
func kubeRootCAConfigMap() *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      K8sRootCA,
			Namespace: common.OperatorNamespace,
			UID:       "root-ca-uid",
		},
	}
}

// decodeLoginField base64-decodes one of the Vault login payload's encoded
// fields (iam_request_url, iam_request_body, iam_request_headers).
func decodeLoginField(t *testing.T, loginData map[string]interface{}, key string) string {
	t.Helper()

	raw, ok := loginData[key].(string)
	require.Truef(t, ok, "login payload is missing string field %q", key)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	require.NoError(t, err)
	return string(decoded)
}

// decodeLoginHeaders returns the signed headers carried in the Vault login
// payload. http.Header canonicalizes keys, so look them up with
// http.CanonicalHeaderKey.
func decodeLoginHeaders(t *testing.T, loginData map[string]interface{}) map[string][]string {
	t.Helper()

	var headers map[string][]string
	require.NoError(t, json.Unmarshal([]byte(decodeLoginField(t, loginData, "iam_request_headers")), &headers))
	return headers
}

// loginAuthorization returns the SigV4 Authorization header from the login
// payload. It carries the signing identity's access key ID and the credential
// scope, so it is the authoritative answer to "which credentials signed this?".
func loginAuthorization(t *testing.T, loginData map[string]interface{}) string {
	t.Helper()

	headers := decodeLoginHeaders(t, loginData)
	require.NotEmpty(t, headers["Authorization"],
		"the login request must carry a SigV4 Authorization header")
	return headers["Authorization"][0]
}

// staticAWSConfig builds an aws.Config that resolves to fixed credentials
// without any network access.
func staticAWSConfig(region string, creds aws.Credentials) *aws.Config {
	return &aws.Config{
		Region:      region,
		Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: creds}),
	}
}

// imdsRejector stands in for the EC2 instance metadata service, recording every
// attempt to reach it and refusing to supply credentials. Tests use it to prove
// VSO did not silently fall back to node credentials.
type imdsRejector struct {
	mu   sync.Mutex
	hits []string
}

func (f *imdsRejector) Hits() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

// newRejectingIMDS starts the fake metadata service and points the SDK at it.
func newRejectingIMDS(t *testing.T) *imdsRejector {
	t.Helper()

	rej := &imdsRejector{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rej.mu.Lock()
		rej.hits = append(rej.hits, r.URL.Path)
		rej.mu.Unlock()
		http.Error(w, "no instance role available", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", srv.URL)
	return rej
}

const (
	nodeAccessKeyID     = "AKIANODECREDS"
	nodeSecretAccessKey = "node-secret-access-key"
	nodeSessionToken    = "node-session-token"
	nodeRoleName        = "vso-node-instance-role"
)

const assumeRoleResponse = `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>AKIAASSUMEDROLE</AccessKeyId>
      <SecretAccessKey>assumed-secret</SecretAccessKey>
      <SessionToken>assumed-session-token</SessionToken>
      <Expiration>2999-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleResult>
</AssumeRoleResponse>`

// fakeIMDS stands in for the EC2 instance metadata service, serving node
// (instance profile) credentials over the IMDSv2 flow and recording every path
// requested.
type fakeIMDS struct {
	mu   sync.Mutex
	hits []string
}

func (f *fakeIMDS) record(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits = append(f.hits, path)
}

func (f *fakeIMDS) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.hits...)
}

func (f *fakeIMDS) start(t *testing.T) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.record(r.URL.Path)

		switch {
		case r.Method == http.MethodPut && r.URL.Path == "/latest/api/token":
			_, _ = w.Write([]byte("fake-imds-v2-token"))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/":
			_, _ = w.Write([]byte(nodeRoleName))
		case r.URL.Path == "/latest/meta-data/iam/security-credentials/"+nodeRoleName:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"Code":            "Success",
				"LastUpdated":     "2026-01-01T00:00:00Z",
				"Type":            "AWS-HMAC",
				"AccessKeyId":     nodeAccessKeyID,
				"SecretAccessKey": nodeSecretAccessKey,
				"Token":           nodeSessionToken,
				"Expiration":      "2999-01-01T00:00:00Z",
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)

	return srv
}

// stsEndpointResolverFunc adapts a function to sts.EndpointResolverV2 so tests
// can point the SDK at a local httptest server.
type stsEndpointResolverFunc func(context.Context, sts.EndpointParameters) (smithyendpoints.Endpoint, error)

func (f stsEndpointResolverFunc) ResolveEndpoint(ctx context.Context, params sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return f(ctx, params)
}

// ─── endpoint resolvers, helpers ───

// ─── region precedence ───

// ─── STS failure propagation ───

// stsErrorResponse renders an STS query-protocol error document.
func stsErrorResponse(code, message string) string {
	return `<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>` + code + `</Code>
    <Message>` + message + `</Message>
  </Error>
  <RequestId>00000000-0000-0000-0000-000000000000</RequestId>
</ErrorResponse>`
}

// ─── consolidated suites ───

// Test_getCredentialsConfig covers how a VaultAuth's spec.aws block, the
// referenced credentials Secret, and the resolved IRSA config are translated
// into an awsutil.CredentialsConfig.
//
// Region deserves the extra cases: its value is produced by two layers that
// have to agree. awsutil.NewCredentialsConfig resolves the environment tiers
// and the us-east-1 default, then getCredentialsConfig overlays
// spec.aws.region on top, giving
// explicit spec > AWS_REGION > AWS_DEFAULT_REGION > us-east-1.
func Test_getCredentialsConfig(t *testing.T) {
	tests := map[string]struct {
		spec       *secretsv1beta1.VaultAuthConfigAWS
		secret     *corev1.Secret
		irsaConfig *IRSAConfig
		irsaToken  string
		awsRegion  string
		awsDefault string
		// sharedCredsFile sets AWS_SHARED_CREDENTIALS_FILE; unsetSharedCreds
		// clears it so the SDK default path applies.
		sharedCredsFile  string
		unsetSharedCreds bool
		check            func(t *testing.T, cfg *awsutil.CredentialsConfig)
	}{
		"explicit spec region outranks both environment variables": {
			spec:       &secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "eu-west-1"},
			awsRegion:  "us-west-2",
			awsDefault: "ap-south-1",
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "eu-west-1", cfg.Region)
			},
		},
		"AWS_REGION is used when the spec omits a region": {
			spec:       &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			awsRegion:  "us-west-2",
			awsDefault: "ap-south-1",
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "us-west-2", cfg.Region)
			},
		},
		"AWS_DEFAULT_REGION is used when AWS_REGION is unset": {
			spec:       &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			awsDefault: "ap-south-1",
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "ap-south-1", cfg.Region)
			},
		},
		"falls back to us-east-1 when no region is configured anywhere": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, awsutil.DefaultRegion, cfg.Region)
			},
		},
		"uses AWS_SHARED_CREDENTIALS_FILE as the shared credentials path": {
			spec:            &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			sharedCredsFile: "/tmp/vso-test-credentials",
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "/tmp/vso-test-credentials", cfg.Filename,
					"awsutil passes Filename to WithSharedCredentialsFiles, so it must point at the configured file")
			},
		},
		"falls back to the SDK default shared credentials path when unset": {
			spec:             &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			unsetSharedCreds: true,
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, awsconfig.DefaultSharedCredentialsFilename(), cfg.Filename,
					"an empty Filename would override the SDK's normal lookup with an empty path")
			},
		},
		"sets RoleSessionName from spec": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r", SessionName: "my-session"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "my-session", cfg.RoleSessionName)
			},
		},
		"sets STSEndpointResolver when stsEndpoint is specified": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r", STSEndpoint: "https://sts.local"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.NotNil(t, cfg.STSEndpointResolver)
			},
		},
		"STSEndpointResolver is nil when stsEndpoint is not specified": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Nil(t, cfg.STSEndpointResolver)
			},
		},
		"sets IAMEndpointResolver when iamEndpoint is specified": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r", IAMEndpoint: "https://iam.local"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.NotNil(t, cfg.IAMEndpointResolver)
			},
		},
		"reads static credentials from the referenced Secret": {
			spec: &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			secret: &corev1.Secret{Data: map[string][]byte{
				consts.AWSAccessKeyID:     []byte("AKIA"),
				consts.AWSSecretAccessKey: []byte("SECRET"),
				consts.AWSSessionToken:    []byte("TOKEN"),
			}},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "AKIA", cfg.AccessKey)
				assert.Equal(t, "SECRET", cfg.SecretKey)
				assert.Equal(t, "TOKEN", cfg.SessionToken)
			},
		},
		"sets RoleARN from the resolved IRSA config": {
			spec:       &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			irsaConfig: &IRSAConfig{RoleARN: "arn:aws:iam::123:role/test"},
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "arn:aws:iam::123:role/test", cfg.RoleARN)
			},
		},
		"sets WebIdentityToken when an IRSA token is provided": {
			spec:       &secretsv1beta1.VaultAuthConfigAWS{Role: "r"},
			irsaConfig: &IRSAConfig{RoleARN: "arn:aws:iam::123:role/test"},
			irsaToken:  "my-token",
			check: func(t *testing.T, cfg *awsutil.CredentialsConfig) {
				assert.Equal(t, "my-token", cfg.WebIdentityToken)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", tt.awsRegion)
			t.Setenv("AWS_DEFAULT_REGION", tt.awsDefault)
			if tt.sharedCredsFile != "" {
				t.Setenv("AWS_SHARED_CREDENTIALS_FILE", tt.sharedCredsFile)
			}
			if tt.unsetSharedCreds {
				t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "")
			}

			p := &AWSCredentialProvider{
				authObj: &secretsv1beta1.VaultAuth{
					Spec: secretsv1beta1.VaultAuthSpec{AWS: tt.spec},
				},
			}

			secret := tt.secret
			if secret == nil {
				secret = &corev1.Secret{}
			}

			cfg, err := p.getCredentialsConfig(secret, tt.irsaConfig, tt.irsaToken)
			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

// Test_GetCreds_IRSA exercises the full AWSCredentialProvider.GetCreds path
// with irsaServiceAccount as the only configured credential source.
//
// Every case runs against a custom stsEndpoint, so each one also proves that
// credential retrieval - not just the final login signature - is routed through
// the configured endpoint, and that the login request is signed with the
// identity returned by AssumeRoleWithWebIdentity rather than by any other
// provider in the chain.
func Test_GetCreds_IRSA(t *testing.T) {
	const (
		namespace    = "vso-test-ns"
		saName       = "vso-irsa-sa"
		roleARN      = "arn:aws:iam::123456789012:role/vso-irsa-role"
		saToken      = "header.irsa-service-account-token.signature"
		vaultRole    = "vso-vault-role"
		assumedKeyID = "AKIAIRSAONLY"
		assumedToken = "irsa-session-token"
	)

	tests := map[string]struct {
		annotations map[string]string
		sessionName string
		// operatorTokenFile seeds the operator pod's own IRSA environment,
		// which must never displace the VaultAuth's ServiceAccount token.
		operatorTokenFile   bool
		operatorRoleARN     string
		expectedAudience    string
		expectedExpiration  int64
		expectedRoleARN     string
		expectedSessionName string
		expectedWebIDToken  string
	}{
		"custom audience and expiration annotations": {
			annotations: map[string]string{
				AWSAnnotationRole:            roleARN,
				AWSAnnotationAudience:        "vso.test.audience",
				AWSAnnotationTokenExpiration: "3600",
			},
			sessionName:         "vso-session",
			expectedAudience:    "vso.test.audience",
			expectedExpiration:  3600,
			expectedRoleARN:     roleARN,
			expectedSessionName: "vso-session",
			expectedWebIDToken:  saToken,
		},
		"defaults applied when only the role-arn annotation is present": {
			annotations:        map[string]string{AWSAnnotationRole: roleARN},
			expectedAudience:   AWSDefaultAudience,
			expectedExpiration: AWSDefaultTokenExpiration,
			expectedRoleARN:    roleARN,
			expectedWebIDToken: saToken,
		},
		"inline ServiceAccount token takes precedence over the operator pod's token file": {
			annotations:         map[string]string{AWSAnnotationRole: roleARN},
			sessionName:         "vso-session",
			operatorTokenFile:   true,
			operatorRoleARN:     "arn:aws:iam::999999999999:role/operator-inherited-role",
			expectedAudience:    AWSDefaultAudience,
			expectedExpiration:  AWSDefaultTokenExpiration,
			expectedRoleARN:     roleARN,
			expectedSessionName: "vso-session",
			expectedWebIDToken:  saToken,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")

			if tt.operatorTokenFile {
				f := filepath.Join(t.TempDir(), "operator-token")
				require.NoError(t, os.WriteFile(f, []byte("operator-pod-jwt"), 0o600))
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", f)
			}
			if tt.operatorRoleARN != "" {
				t.Setenv("AWS_ROLE_ARN", tt.operatorRoleARN)
			}

			var mu sync.Mutex
			imds := newRejectingIMDS(t)
			stsRec := newSTSRecorder(t, http.StatusOK, assumeRoleWithWebIdentityResponse)

			sa := newIRSAServiceAccount(saName, namespace, roleARN, tt.annotations)

			var tokenRequests []authenticationv1.TokenRequestSpec
			client := withTokenRequests(newFakeClient(t, sa), saToken, &tokenRequests, &mu).Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:               vaultRole,
						Region:             "us-east-1",
						SessionName:        tt.sessionName,
						STSEndpoint:        stsRec.URL,
						IRSAServiceAccount: saName,
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, namespace))

			loginData, err := provider.GetCreds(ctx, client)
			require.NoError(t, err, "IRSA-only auth must succeed without any node or ambient AWS credentials")

			mu.Lock()
			defer mu.Unlock()

			require.Empty(t, imds.Hits(),
				"VSO must not fall back to EC2 instance metadata / node credentials when irsaServiceAccount is configured")

			// The ServiceAccount token was requested with the annotation-derived
			// audience and expiration.
			require.Len(t, tokenRequests, 1, "expected exactly one ServiceAccount TokenRequest")
			assert.Equal(t, []string{tt.expectedAudience}, tokenRequests[0].Audiences)
			require.NotNil(t, tokenRequests[0].ExpirationSeconds)
			assert.Equal(t, tt.expectedExpiration, *tokenRequests[0].ExpirationSeconds)

			// Credential retrieval went through the configured stsEndpoint and
			// presented the VaultAuth's own token and role.
			calls := stsRec.Calls()
			require.Len(t, calls, 1, "expected exactly one STS call")
			call := calls[0]
			assert.Equal(t, "AssumeRoleWithWebIdentity", call.Get("Action"))
			assert.Equal(t, tt.expectedWebIDToken, call.Get("WebIdentityToken"),
				"the requested ServiceAccount token must be the one presented to STS")
			assert.Equal(t, tt.expectedRoleARN, call.Get("RoleArn"),
				"must assume the VaultAuth's role, not one inherited from the operator environment")
			if tt.expectedSessionName != "" {
				assert.Equal(t, tt.expectedSessionName, call.Get("RoleSessionName"))
			}

			// The login payload targets the configured endpoint and is signed
			// with the assumed-role identity.
			assert.Equal(t, vaultRole, loginData["role"])

			loginURL, err := url.Parse(decodeLoginField(t, loginData, "iam_request_url"))
			require.NoError(t, err)
			stsURL, err := url.Parse(stsRec.URL)
			require.NoError(t, err)
			assert.Equal(t, stsURL.Host, loginURL.Host,
				"login request must target the configured STS endpoint")

			assert.Contains(t, loginAuthorization(t, loginData), assumedKeyID,
				"login request must be signed with the web identity credentials")
			assert.Equal(t, []string{assumedToken},
				decodeLoginHeaders(t, loginData)["X-Amz-Security-Token"])
		})
	}
}

// Test_GetCreds_NodeCredentials exercises GetCreds when neither secretRef nor
// irsaServiceAccount is configured, so the node/instance-profile credentials
// from EC2 IMDS are the only source, with and without role assumption layered
// on top via AWS_ROLE_ARN.
func Test_GetCreds_NodeCredentials(t *testing.T) {
	const (
		assumeRoleARN = "arn:aws:iam::123456789012:role/vso-target-role"
		sessionName   = "vso-node-session"
	)

	tests := map[string]struct {
		roleARN string
		// expectedSigningKeyID is the access key that must sign the Vault
		// login request; unexpectedKeyID must not appear in the signature.
		expectedSigningKeyID string
		unexpectedKeyID      string
		expectedSessionToken string
		expectSTSCall        bool
	}{
		"assumes the configured role when AWS_ROLE_ARN is set": {
			roleARN:              assumeRoleARN,
			expectedSigningKeyID: "AKIAASSUMEDROLE",
			unexpectedKeyID:      nodeAccessKeyID,
			expectedSessionToken: "assumed-session-token",
			expectSTSCall:        true,
		},
		"uses node credentials directly when no role is configured": {
			expectedSigningKeyID: nodeAccessKeyID,
			unexpectedKeyID:      "AKIAASSUMEDROLE",
			expectedSessionToken: nodeSessionToken,
			expectSTSCall:        false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")

			imds := &fakeIMDS{}
			imdsServer := imds.start(t)
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)

			if tt.roleARN != "" {
				// awsutil.NewCredentialsConfig reads this straight from the
				// environment into CredentialsConfig.RoleARN; VSO has no spec
				// field for it.
				t.Setenv("AWS_ROLE_ARN", tt.roleARN)
			}

			stsRec := newSTSRecorder(t, http.StatusOK, assumeRoleResponse)

			client := newFakeClient(t, kubeRootCAConfigMap()).Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: "vso-test-ns"},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						SessionName: sessionName,
						STSEndpoint: stsRec.URL,
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, "vso-test-ns"))

			loginData, err := provider.GetCreds(ctx, client)
			require.NoError(t, err)

			assert.Contains(t, imds.paths(), "/latest/meta-data/iam/security-credentials/",
				"expected the EC2 role provider to supply the node credentials")

			calls := stsRec.Calls()

			if tt.expectSTSCall {
				require.Len(t, calls, 1, "expected exactly one STS call")
				assert.Equal(t, "AssumeRole", calls[0].Get("Action"),
					"the configured role must be assumed rather than used directly")
				assert.Equal(t, assumeRoleARN, calls[0].Get("RoleArn"))
				assert.Equal(t, sessionName, calls[0].Get("RoleSessionName"))
			} else {
				assert.Empty(t, calls,
					"no role is configured, so nothing may be assumed")
			}

			headers := decodeLoginHeaders(t, loginData)
			authHeader := loginAuthorization(t, loginData)

			assert.Contains(t, authHeader, tt.expectedSigningKeyID,
				"Vault login must be signed with the expected identity")
			assert.NotContains(t, authHeader, tt.unexpectedKeyID,
				"Vault login must not be signed with the other identity")
			assert.Equal(t, []string{tt.expectedSessionToken}, headers["X-Amz-Security-Token"])
		})
	}

	// The override itself must be inert when no role is configured, so plain
	// node/instance-profile authentication keeps the chain's own provider.
	t.Run("override leaves the chain untouched when no role is configured", func(t *testing.T) {
		isolateAWSEnvironment(t)
		t.Setenv("AWS_REGION", "us-east-1")

		imds := &fakeIMDS{}
		imdsServer := imds.start(t)
		t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)

		cfg, err := awsutil.NewCredentialsConfig()
		require.NoError(t, err)
		cfg.Region = "us-east-1"
		// No RoleARN, no web identity token.

		awsCfg, err := cfg.GenerateCredentialChain(context.Background())
		require.NoError(t, err)

		before := awsCfg.Credentials
		applyCredentialsOverride(awsCfg, cfg, nil, "")
		assert.Same(t, before, awsCfg.Credentials,
			"override must leave the credential provider untouched when no role is configured")

		creds, err := awsCfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err)
		assert.Equal(t, nodeAccessKeyID, creds.AccessKeyID, "the chain resolves to node credentials")
		assert.True(t, strings.Contains(creds.Source, "IMDS") || strings.Contains(creds.Source, "EC2"),
			"expected IMDS-sourced credentials, got source %q", creds.Source)
	})
}

// Test_applyCredentialsOverride_AmbientWebIdentity covers the web identity
// paths that are driven by the operator pod's own environment rather than by an
// irsaServiceAccount on the VaultAuth.
//
// awsutil seeds CredentialsConfig.WebIdentityTokenFile from
// AWS_WEB_IDENTITY_TOKEN_FILE, and a token may also be supplied inline. In both
// cases the override still has to build a web identity provider and route it
// through the configured stsEndpoint - GenerateCredentialChain on its own does
// neither. These are distinct switch branches from the explicit-IRSA case.
func Test_applyCredentialsOverride_AmbientWebIdentity(t *testing.T) {
	const roleARN = "arn:aws:iam::123456789012:role/ambient-web-identity-role"

	tests := map[string]struct {
		useTokenFile  bool
		token         string
		expectedToken string
	}{
		"token sourced from AWS_WEB_IDENTITY_TOKEN_FILE": {
			useTokenFile:  true,
			token:         "token-file-contents",
			expectedToken: "token-file-contents",
		},
		"token supplied inline on the credentials config": {
			token:         "inline-token-contents",
			expectedToken: "inline-token-contents",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")

			stsRec := newSTSRecorder(t, http.StatusOK, assumeRoleWithWebIdentityResponse)
			stsURL, err := url.Parse(stsRec.URL)
			require.NoError(t, err)

			cfg, err := awsutil.NewCredentialsConfig()
			require.NoError(t, err)
			cfg.Region = "us-east-1"
			cfg.RoleARN = roleARN
			if tt.useTokenFile {
				f := filepath.Join(t.TempDir(), "token")
				require.NoError(t, os.WriteFile(f, []byte(tt.token), 0o600))
				cfg.WebIdentityTokenFile = f
			} else {
				cfg.WebIdentityToken = tt.token
			}
			cfg.STSEndpointResolver = stsEndpointResolverFunc(
				func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
					return smithyendpoints.Endpoint{URI: *stsURL}, nil
				})

			awsCfg, err := cfg.GenerateCredentialChain(context.Background())
			require.NoError(t, err)

			// Not an explicit irsaServiceAccount request, so nil/"" is passed.
			applyCredentialsOverride(awsCfg, cfg, nil, "")

			creds, err := awsCfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err, "credential retrieval must succeed through the custom STS endpoint")
			assert.Equal(t, "AKIAIRSAONLY", creds.AccessKeyID,
				"credentials must come from AssumeRoleWithWebIdentity")

			calls := stsRec.Calls()

			require.Len(t, calls, 1, "expected exactly one STS call, routed to the custom endpoint")
			assert.Equal(t, "AssumeRoleWithWebIdentity", calls[0].Get("Action"))
			assert.Equal(t, roleARN, calls[0].Get("RoleArn"))
			assert.Equal(t, tt.expectedToken, calls[0].Get("WebIdentityToken"))
		})
	}
}

// Test_GetCreds_SecretRef exercises the third documented credential source:
// static AWS credentials supplied through a Kubernetes Secret.
//
// Static credentials need no STS round trip, so the login request must be
// signed directly with the Secret's keys. The second case is the end-to-end
// form of the precedence guarantee: an operator pod running under its own IRSA
// leaks AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE into the process, and the
// Secret's credentials must still be the ones that sign the Vault login.
func Test_GetCreds_SecretRef(t *testing.T) {
	const (
		namespace  = "vso-test-ns"
		secretName = "aws-static-creds"
		accessKey  = "AKIAFROMSECRET"
		secretKey  = "secret-access-key-from-k8s-secret"
		sessToken  = "session-token-from-k8s-secret"
	)

	tests := map[string]struct {
		operatorIRSAEnv bool
	}{
		"signs the login request with the Secret's static credentials": {},
		"Secret credentials survive an operator pod running under IRSA": {
			operatorIRSAEnv: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")

			if tt.operatorIRSAEnv {
				f := filepath.Join(t.TempDir(), "operator-token")
				require.NoError(t, os.WriteFile(f, []byte("operator-pod-jwt"), 0o600))
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", f)
				t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::999999999999:role/operator-inherited-role")
			}

			// Any STS traffic at all would mean VSO tried to assume a role
			// instead of using the Secret's credentials directly.
			stsRec := newSTSRecorder(t, http.StatusOK, assumeRoleWithWebIdentityResponse)

			credsSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: secretName, Namespace: namespace, UID: "creds-secret-uid",
				},
				Data: map[string][]byte{
					consts.AWSAccessKeyID:     []byte(accessKey),
					consts.AWSSecretAccessKey: []byte(secretKey),
					consts.AWSSessionToken:    []byte(sessToken),
				},
			}
			client := newFakeClient(t, credsSecret).Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						STSEndpoint: stsRec.URL,
						SecretRef:   secretName,
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, namespace))
			// Init keys its cache identity off the Secret on this path.
			assert.Equal(t, types.UID("creds-secret-uid"), provider.GetUID())
			assert.Equal(t, namespace, provider.GetNamespace())

			loginData, err := provider.GetCreds(ctx, client)
			require.NoError(t, err)

			calls := stsRec.Calls()
			assert.Empty(t, calls,
				"static credentials require no STS call; any call means a role was wrongly assumed")

			headers := decodeLoginHeaders(t, loginData)
			authHeader := loginAuthorization(t, loginData)

			assert.Contains(t, authHeader, accessKey,
				"the Vault login must be signed with the Secret's credentials")
			assert.NotContains(t, authHeader, "AKIAIRSAONLY",
				"the Vault login must not be signed with assumed-role credentials")
			assert.Equal(t, []string{sessToken}, headers["X-Amz-Security-Token"])
			assert.Equal(t, "vso-vault-role", loginData["role"])
		})
	}
}

// Test_GetCreds_SharedCredentialsFile covers authentication via a shared AWS
// credentials file, for both the default and a named profile.
//
// awsutil passes CredentialsConfig.Filename to
// config.WithSharedCredentialsFiles unconditionally. VSO leaves Filename empty,
// which replaced the SDK's normal file lookup with an empty path and made
// GenerateCredentialChain fail outright with "failed to get shared config
// profile". getCredentialsConfig now resolves the path the way the SDK does.
//
// Each case asserts which credentials sign the Vault login, and that no STS
// call occurs, since shared-file credentials are static.
func Test_GetCreds_SharedCredentialsFile(t *testing.T) {
	const (
		namespace = "vso-test-ns"
		profileID = "AKIAFROMPROFILE"
	)

	tests := map[string]struct {
		profile    string
		awsProfile string
	}{
		"default profile": {
			profile: "default",
		},
		"named profile selected by AWS_PROFILE": {
			profile:    "vso-named-profile",
			awsProfile: "vso-named-profile",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")
			t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

			credsFile := filepath.Join(t.TempDir(), "credentials")
			require.NoError(t, os.WriteFile(credsFile, []byte(
				"["+tt.profile+"]\n"+
					"aws_access_key_id = "+profileID+"\n"+
					"aws_secret_access_key = profile-secret-access-key\n"+
					"aws_session_token = profile-session-token\n"), 0o600))
			t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credsFile)
			if tt.awsProfile != "" {
				t.Setenv("AWS_PROFILE", tt.awsProfile)
			}

			stsRec := newSTSRecorder(t, http.StatusOK, assumeRoleWithWebIdentityResponse)

			client := newFakeClient(t, kubeRootCAConfigMap()).Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						STSEndpoint: stsRec.URL,
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, namespace))

			loginData, err := provider.GetCreds(ctx, client)
			require.NoError(t, err,
				"shared-credentials-file auth must succeed; a chain error here means "+
					"the shared file lookup was overridden with an empty path")

			calls := stsRec.Calls()
			assert.Empty(t, calls, "shared-file credentials are static and need no STS call")

			headers := decodeLoginHeaders(t, loginData)
			authHeader := loginAuthorization(t, loginData)

			assert.Contains(t, authHeader, profileID,
				"the Vault login must be signed with the shared profile's credentials")
			assert.Equal(t, []string{"profile-session-token"}, headers["X-Amz-Security-Token"])
		})
	}
}

// ─── focused unit tests ───

// Test_buildSignedGetCallerIdentityRequest covers construction and SigV4
// signing of the sts:GetCallerIdentity request that becomes the Vault login
// payload.
func Test_buildSignedGetCallerIdentityRequest(t *testing.T) {
	endpoint := stsSigningEndpoint{
		requestURL:    "https://sts.us-east-1.amazonaws.com",
		signingName:   stsSigningName,
		signingRegion: "us-east-1",
	}

	longTermCreds := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}
	temporaryCreds := aws.Credentials{
		AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoXnyc4lcK4w=",
		Source:          "test",
	}

	tests := map[string]struct {
		creds       aws.Credentials
		headerValue string
		check       func(t *testing.T, req *http.Request, body string)
	}{
		"produces the GetCallerIdentity POST and body": {
			creds: longTermCreds,
			check: func(t *testing.T, req *http.Request, body string) {
				assert.Equal(t, http.MethodPost, req.Method)
				assert.Equal(t, stsGetCallerIdentityBody, body)
				assert.Equal(t, stsContentType, req.Header.Get("Content-Type"))
			},
		},
		"targets the resolved endpoint": {
			creds: longTermCreds,
			check: func(t *testing.T, req *http.Request, _ string) {
				assert.Equal(t, "https://sts.us-east-1.amazonaws.com", req.URL.String())
			},
		},
		"signs the request with SigV4": {
			creds: longTermCreds,
			check: func(t *testing.T, req *http.Request, _ string) {
				auth := req.Header.Get("Authorization")
				require.NotEmpty(t, auth, "a signed request must carry an Authorization header")
				assert.Contains(t, auth, "AWS4-HMAC-SHA256")
			},
		},
		"sets the Vault server ID header when a header value is configured": {
			creds:       longTermCreds,
			headerValue: "vault.example.com",
			check: func(t *testing.T, req *http.Request, _ string) {
				assert.Equal(t, "vault.example.com", req.Header.Get(iamServerIDHeader))
			},
		},
		"omits the Vault server ID header when no header value is configured": {
			creds: longTermCreds,
			check: func(t *testing.T, req *http.Request, _ string) {
				assert.Empty(t, req.Header.Get(iamServerIDHeader))
			},
		},
		"forwards the session token for temporary credentials": {
			creds: temporaryCreds,
			check: func(t *testing.T, req *http.Request, _ string) {
				// The SDK's v4 signer emits the session token as
				// X-Amz-Security-Token; Vault rejects the login without it.
				assert.Equal(t, "AQoXnyc4lcK4w=", req.Header.Get("X-Amz-Security-Token"))
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			req, body, err := buildSignedGetCallerIdentityRequest(
				context.Background(), tt.creds, endpoint, tt.headerValue)
			require.NoError(t, err)
			tt.check(t, req, body)
		})
	}
}

// Test_generateLoginData covers the Vault login payload built from a resolved
// aws.Config: its required fields, its encoding, and the signing identity,
// region and endpoint it ends up carrying.
func Test_generateLoginData(t *testing.T) {
	staticCreds := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}
	temporaryCreds := aws.Credentials{
		AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		SessionToken:    "AQoXnyc4lcK4w=",
		Source:          "test",
	}

	tests := map[string]struct {
		awsCfg      *aws.Config
		headerValue string
		stsEndpoint string
		expectedErr string
		check       func(t *testing.T, loginData map[string]interface{})
	}{
		"nil config is rejected": {
			awsCfg:      nil,
			expectedErr: "AWS credentials are not configured",
		},
		"config without a credentials provider is rejected": {
			awsCfg:      &aws.Config{},
			expectedErr: "AWS credentials are not configured",
		},
		"empty credentials are rejected": {
			awsCfg:      staticAWSConfig("us-east-1", aws.Credentials{}),
			expectedErr: "retrieved AWS credentials are empty",
		},
		"produces every field the Vault aws auth method requires": {
			awsCfg: staticAWSConfig("us-east-1", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				for _, key := range []string{
					"iam_http_request_method",
					"iam_request_url",
					"iam_request_headers",
					"iam_request_body",
				} {
					assert.Contains(t, loginData, key, "missing key: %s", key)
				}
				assert.Equal(t, http.MethodPost, loginData["iam_http_request_method"])
			},
		},
		"encodes the STS URL": {
			awsCfg: staticAWSConfig("us-east-1", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				assert.Contains(t, decodeLoginField(t, loginData, "iam_request_url"),
					"sts.us-east-1.amazonaws.com")
			},
		},
		"encodes the GetCallerIdentity body": {
			awsCfg: staticAWSConfig("us-east-1", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				assert.Equal(t, stsGetCallerIdentityBody,
					decodeLoginField(t, loginData, "iam_request_body"))
			},
		},
		"encodes signed headers": {
			awsCfg: staticAWSConfig("us-east-1", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				assert.Contains(t, loginAuthorization(t, loginData), "AWS4-HMAC-SHA256")
			},
		},
		"includes the configured Vault server ID header": {
			awsCfg:      staticAWSConfig("us-east-1", staticCreds),
			headerValue: "vault.example.com",
			check: func(t *testing.T, loginData map[string]interface{}) {
				headers := decodeLoginHeaders(t, loginData)
				// http.Header canonicalizes keys:
				// "X-Vault-AWS-IAM-Server-ID" -> "X-Vault-Aws-Iam-Server-Id".
				vals, ok := headers[http.CanonicalHeaderKey(iamServerIDHeader)]
				require.True(t, ok, "header %q should be present", iamServerIDHeader)
				assert.Equal(t, "vault.example.com", vals[0])
			},
		},
		"forwards the session token for temporary credentials": {
			awsCfg: staticAWSConfig("us-east-1", temporaryCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				headers := decodeLoginHeaders(t, loginData)
				require.NotEmpty(t, headers["X-Amz-Security-Token"],
					"X-Amz-Security-Token must be present for temporary credentials")
				assert.Equal(t, "AQoXnyc4lcK4w=", headers["X-Amz-Security-Token"][0])
			},
		},
		"honors a custom STS endpoint": {
			awsCfg:      staticAWSConfig("us-east-1", staticCreds),
			stsEndpoint: "https://localstack:4566",
			check: func(t *testing.T, loginData map[string]interface{}) {
				assert.Contains(t, decodeLoginField(t, loginData, "iam_request_url"),
					"localstack:4566")
			},
		},
		"falls back to the default region when the config has none": {
			awsCfg: staticAWSConfig("", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				assert.Contains(t, decodeLoginField(t, loginData, "iam_request_url"),
					awsutil.DefaultRegion)
			},
		},
		"the config region determines the SigV4 credential scope": {
			// The region only matters if it reaches the signature: a login
			// signed under the wrong regional scope is rejected by STS, so
			// assert on the Authorization header rather than the URL alone.
			awsCfg: staticAWSConfig("eu-west-1", staticCreds),
			check: func(t *testing.T, loginData map[string]interface{}) {
				auth := loginAuthorization(t, loginData)
				assert.Contains(t, auth, "/eu-west-1/sts/aws4_request",
					"the configured region must appear in the SigV4 credential scope")
				assert.NotContains(t, auth, awsutil.DefaultRegion)
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			loginData, err := generateLoginData(
				context.Background(), tt.awsCfg, tt.headerValue, tt.stsEndpoint)

			if tt.expectedErr != "" {
				require.ErrorContains(t, err, tt.expectedErr)
				return
			}
			require.NoError(t, err)
			tt.check(t, loginData)
		})
	}
}

// Test_customEndpointResolvers covers the STS and IAM endpoint resolvers
// installed by getCredentialsConfig when spec.aws.stsEndpoint or
// spec.aws.iamEndpoint is set.
func Test_customEndpointResolvers(t *testing.T) {
	tests := map[string]struct {
		endpointURL string
		// region is passed to the STS resolver to confirm a custom endpoint
		// wins over regional resolution. It is ignored by the IAM case.
		region      string
		expectedURI string
		stsErr      string
		iamErr      string
	}{
		"resolves the configured endpoint": {
			endpointURL: "https://endpoint.example.internal:8443/path",
			expectedURI: "https://endpoint.example.internal:8443/path",
		},
		"a custom endpoint outranks the region": {
			endpointURL: "https://endpoint.example.internal",
			region:      "eu-west-1",
			expectedURI: "https://endpoint.example.internal",
		},
		"a malformed URL is reported": {
			endpointURL: "http://[::1]:namedport",
			stsErr:      "failed to parse custom STS endpoint URL",
			iamErr:      "failed to parse custom IAM endpoint URL",
		},
	}

	for name, tt := range tests {
		t.Run("STS/"+name, func(t *testing.T) {
			params := sts.EndpointParameters{}
			if tt.region != "" {
				params.Region = aws.String(tt.region)
			}
			r := &customSTSEndpointResolver{endpointURL: tt.endpointURL}
			ep, err := r.ResolveEndpoint(context.Background(), params)
			if tt.stsErr != "" {
				require.ErrorContains(t, err, tt.stsErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedURI, ep.URI.String())
		})

		t.Run("IAM/"+name, func(t *testing.T) {
			r := &customIAMEndpointResolver{endpointURL: tt.endpointURL}
			ep, err := r.ResolveEndpoint(context.Background(), iam.EndpointParameters{})
			if tt.iamErr != "" {
				require.ErrorContains(t, err, tt.iamErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.expectedURI, ep.URI.String())
		})
	}
}

// Test_sortedKeys guards the deterministic ordering applyCredentialsOverride
// relies on when translating RoleTags into sts:AssumeRole Tags.member.N entries.
func Test_sortedKeys(t *testing.T) {
	tests := map[string]struct {
		input    map[string]string
		expected []string
	}{
		"sorts keys alphabetically": {
			input:    map[string]string{"z": "1", "a": "2", "b": "3"},
			expected: []string{"a", "b", "z"},
		},
		"empty map yields no keys": {
			input:    map[string]string{},
			expected: nil,
		},
		"nil map yields no keys": {
			input:    nil,
			expected: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got := sortedKeys(tt.input)
			if len(tt.expected) == 0 {
				assert.Empty(t, got)
				return
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Test_resolvedStaticCredentials covers the guard that keeps
// applyCredentialsOverride from outranking credentials the AWS credential chain
// already selected.
func Test_resolvedStaticCredentials(t *testing.T) {
	tests := map[string]struct {
		provider aws.CredentialsProvider
		expected bool
	}{
		"cached static provider": {
			provider: aws.NewCredentialsCache(
				credentials.NewStaticCredentialsProvider("AKIA", "secret", "")),
			expected: true,
		},
		"bare static provider": {
			provider: credentials.NewStaticCredentialsProvider("AKIA", "secret", ""),
			expected: true,
		},
		"non-static provider that merely returns fixed credentials": {
			// Deliberately narrow: only credentials.StaticCredentialsProvider
			// counts, so role providers are never mistaken for static ones.
			provider: aws.NewCredentialsCache(staticCredentialsProvider{
				creds: aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret"},
			}),
			expected: false,
		},
		"nil provider": {
			provider: nil,
			expected: false,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolvedStaticCredentials(tt.provider))
		})
	}
}

// ─── credential precedence and role assumption ───

// Test_applyCredentialsOverride_PreservesCredentialPrecedence asserts that the
// role-assumption override never outranks credentials the AWS credential chain
// legitimately selected.
//
// When VSO itself runs on EKS under IRSA the operator pod carries AWS_ROLE_ARN
// and AWS_WEB_IDENTITY_TOKEN_FILE. awsutil.NewCredentialsConfig seeds
// CredentialsConfig.RoleARN from AWS_ROLE_ARN, so a VaultAuth that never asked
// for role assumption can still present a non-empty RoleARN inherited from the
// operator's own environment. Acting on that inherited value would sign the
// Vault login as the operator's role instead of the configured identity.
//
// Each case asserts *which* credentials would sign the login, by access key ID,
// rather than merely that credential resolution succeeded.
func Test_applyCredentialsOverride_PreservesCredentialPrecedence(t *testing.T) {
	const (
		operatorRoleARN = "arn:aws:iam::123456789012:role/operator-irsa-role"
		secretKeyID     = "AKIAFROMSECRET"
		envKeyID        = "AKIAFROMENV"
		profileKeyID    = "AKIAFROMPROFILE"
		vaultAuthRole   = "arn:aws:iam::123456789012:role/vaultauth-irsa-role"
	)

	tests := map[string]struct {
		// operatorIRSA seeds the operator pod's own IRSA environment.
		operatorIRSA bool
		envCreds     bool
		secret       *corev1.Secret
		irsaConfig   *IRSAConfig
		irsaToken    string
		// preloadStatic swaps in a static provider to stand in for any
		// static-credential source the chain may settle on.
		preloadStatic bool
		check         func(t *testing.T, awsCfg *aws.Config, before aws.CredentialsProvider)
	}{
		"secretRef credentials survive an inherited AWS_ROLE_ARN": {
			operatorIRSA: true,
			secret: &corev1.Secret{Data: map[string][]byte{
				consts.AWSAccessKeyID:     []byte(secretKeyID),
				consts.AWSSecretAccessKey: []byte("secretFromK8sSecret"),
			}},
			check: func(t *testing.T, awsCfg *aws.Config, _ aws.CredentialsProvider) {
				after, err := awsCfg.Credentials.Retrieve(context.Background())
				require.NoError(t, err, "override must not break credential retrieval")
				assert.Equal(t, secretKeyID, after.AccessKeyID,
					"the login must still be signed with the secretRef credentials, "+
						"not the operator's inherited IRSA role")
			},
		},
		"environment credentials survive an inherited AWS_ROLE_ARN": {
			operatorIRSA: true,
			envCreds:     true,
			check: func(t *testing.T, awsCfg *aws.Config, _ aws.CredentialsProvider) {
				after, err := awsCfg.Credentials.Retrieve(context.Background())
				require.NoError(t, err, "override must not break credential retrieval")
				assert.Equal(t, envKeyID, after.AccessKeyID,
					"the login must still be signed with the environment credentials")
			},
		},
		"override stands down whenever the chain resolved static credentials": {
			operatorIRSA:  true,
			preloadStatic: true,
			check: func(t *testing.T, awsCfg *aws.Config, before aws.CredentialsProvider) {
				assert.Same(t, before, awsCfg.Credentials,
					"override must leave static credentials untouched")
				after, err := awsCfg.Credentials.Retrieve(context.Background())
				require.NoError(t, err)
				assert.Equal(t, profileKeyID, after.AccessKeyID)
			},
		},
		"explicit irsaServiceAccount outranks ambient static credentials": {
			// Ambient static credentials must NOT win here, because the
			// VaultAuth explicitly named an irsaServiceAccount.
			envCreds:   true,
			irsaConfig: &IRSAConfig{RoleARN: vaultAuthRole},
			irsaToken:  "vaultauth-sa-jwt",
			check: func(t *testing.T, awsCfg *aws.Config, _ aws.CredentialsProvider) {
				assert.False(t, resolvedStaticCredentials(awsCfg.Credentials),
					"an explicit irsaServiceAccount must install a role provider, "+
						"not fall back to ambient static credentials")
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)

			if tt.operatorIRSA {
				tokenFile := filepath.Join(t.TempDir(), "token")
				require.NoError(t, os.WriteFile(tokenFile, []byte("operator-pod-jwt"), 0o600))
				t.Setenv("AWS_ROLE_ARN", operatorRoleARN)
				t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
			}
			if tt.envCreds {
				t.Setenv("AWS_ACCESS_KEY_ID", envKeyID)
				t.Setenv("AWS_SECRET_ACCESS_KEY", "secretFromEnv")
			}

			spec := &secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "us-east-1"}
			if tt.irsaConfig != nil {
				spec.IRSAServiceAccount = "irsa-sa"
			}
			p := &AWSCredentialProvider{
				authObj: &secretsv1beta1.VaultAuth{
					Spec: secretsv1beta1.VaultAuthSpec{AWS: spec},
				},
			}

			secret := tt.secret
			if secret == nil {
				secret = &corev1.Secret{}
			}
			cfg, err := p.getCredentialsConfig(secret, tt.irsaConfig, tt.irsaToken)
			require.NoError(t, err)
			if tt.operatorIRSA {
				require.Equal(t, operatorRoleARN, cfg.RoleARN,
					"precondition: awsutil seeds RoleARN from the operator pod's environment")
			}

			awsCfg, err := cfg.GenerateCredentialChain(context.Background())
			require.NoError(t, err)

			if tt.preloadStatic {
				awsCfg.Credentials = aws.NewCredentialsCache(
					credentials.NewStaticCredentialsProvider(profileKeyID, "secretFromProfile", ""))
				require.True(t, resolvedStaticCredentials(awsCfg.Credentials),
					"precondition: the guard recognizes static credentials")
			}

			before := awsCfg.Credentials
			applyCredentialsOverride(awsCfg, cfg, tt.irsaConfig, tt.irsaToken)
			tt.check(t, awsCfg, before)
		})
	}
}

// Test_applyCredentialsOverride_AssumeRole covers the assume-role path taken
// when a role is configured without any web identity token, including the
// optional external ID and session tags, and the role ARN the override must
// act on.
func Test_applyCredentialsOverride_AssumeRole(t *testing.T) {
	const (
		targetRole      = "arn:aws:iam::123456789012:role/vso-target-role"
		operatorRole    = "arn:aws:iam::999999999999:role/operator-inherited-role"
		vaultAuthRole   = "arn:aws:iam::123456789012:role/vaultauth-requested-role"
		irsaTokenForARN = "vaultauth-sa-jwt"
	)

	tests := map[string]struct {
		roleARN      string
		sessionName  string
		externalID   string
		roleTags     map[string]string
		webIDToken   string
		irsaConfig   *IRSAConfig
		irsaToken    string
		stsResponse  string
		expectAction string
		check        func(t *testing.T, call url.Values)
	}{
		"assumes the node role and propagates external ID and tags": {
			roleARN:      targetRole,
			externalID:   "external-id-123",
			roleTags:     map[string]string{"team": "vso", "env": "test"},
			stsResponse:  assumeRoleResponse,
			expectAction: "AssumeRole",
			check: func(t *testing.T, call url.Values) {
				assert.Equal(t, targetRole, call.Get("RoleArn"))
				assert.Equal(t, "external-id-123", call.Get("ExternalId"),
					"RoleExternalId must be propagated")
				// Tags are sorted by key: env, then team.
				assert.Equal(t, "env", call.Get("Tags.member.1.Key"))
				assert.Equal(t, "test", call.Get("Tags.member.1.Value"))
				assert.Equal(t, "team", call.Get("Tags.member.2.Key"))
				assert.Equal(t, "vso", call.Get("Tags.member.2.Value"))
			},
		},
		"propagates the configured session name": {
			roleARN:      targetRole,
			sessionName:  "vso-node-session",
			stsResponse:  assumeRoleResponse,
			expectAction: "AssumeRole",
			check: func(t *testing.T, call url.Values) {
				assert.Equal(t, "vso-node-session", call.Get("RoleSessionName"))
			},
		},
		"assumes the validated role, not one inherited from the environment": {
			// applyCredentialsOverride decides an explicit IRSA request is in
			// play from irsaConfig.RoleARN, so it must assume that same value.
			// credsConfig.RoleARN usually carries it too, but it is also the
			// field awsutil seeds from the operator pod's own AWS_ROLE_ARN;
			// assuming that one would authenticate as the wrong principal.
			roleARN:      operatorRole,
			webIDToken:   irsaTokenForARN,
			irsaConfig:   &IRSAConfig{RoleARN: vaultAuthRole},
			irsaToken:    irsaTokenForARN,
			stsResponse:  assumeRoleWithWebIdentityResponse,
			expectAction: "AssumeRoleWithWebIdentity",
			check: func(t *testing.T, call url.Values) {
				assert.Equal(t, vaultAuthRole, call.Get("RoleArn"),
					"must assume the role the VaultAuth asked for")
				assert.NotEqual(t, operatorRole, call.Get("RoleArn"))
			},
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_REGION", "us-east-1")

			// Node credentials stand in as the assume-role source for the
			// cases that have no web identity token.
			imds := &fakeIMDS{}
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds.start(t).URL)

			stsRec := newSTSRecorder(t, http.StatusOK, tt.stsResponse)

			cfg, err := awsutil.NewCredentialsConfig()
			require.NoError(t, err)
			cfg.Region = "us-east-1"
			cfg.RoleARN = tt.roleARN
			cfg.RoleSessionName = tt.sessionName
			cfg.RoleExternalId = tt.externalID
			cfg.RoleTags = tt.roleTags
			cfg.WebIdentityToken = tt.webIDToken
			cfg.STSEndpointResolver = stsRec.Resolver(t)

			awsCfg, err := cfg.GenerateCredentialChain(context.Background())
			require.NoError(t, err)

			before := awsCfg.Credentials
			applyCredentialsOverride(awsCfg, cfg, tt.irsaConfig, tt.irsaToken)
			assert.NotSame(t, before, awsCfg.Credentials,
				"override must install a role provider when a role is configured")

			_, err = awsCfg.Credentials.Retrieve(context.Background())
			require.NoError(t, err)

			calls := stsRec.Calls()
			require.Len(t, calls, 1, "expected exactly one STS call")
			assert.Equal(t, tt.expectAction, calls[0].Get("Action"))
			tt.check(t, calls[0])
		})
	}
}

// Test_GetCreds_STSErrorPropagates asserts that an STS failure during
// credential retrieval surfaces as a non-nil error from GetCreds on both the
// IRSA and node-role paths.
//
// This guards against a silent fallback. Both paths replace the credential
// chain with a lazily-resolving role provider, so a rejected AssumeRole or
// AssumeRoleWithWebIdentity must abort the login rather than quietly signing it
// with whatever the chain resolved earlier - which would authenticate to Vault
// as the wrong principal.
func Test_GetCreds_STSErrorPropagates(t *testing.T) {
	const namespace = "vso-test-ns"

	stsErrors := map[string]struct{ code, message string }{
		"AccessDenied": {
			code:    "AccessDenied",
			message: "User is not authorized to perform sts:AssumeRole on the requested resource",
		},
		"ExpiredToken": {
			code:    "ExpiredToken",
			message: "The security token included in the request is expired",
		},
	}

	paths := map[string]struct {
		irsa bool
	}{
		"IRSA path":      {irsa: true},
		"node role path": {},
	}

	for errName, stsErr := range stsErrors {
		for pathName, path := range paths {
			t.Run(pathName+" returns an error on "+errName, func(t *testing.T) {
				isolateAWSEnvironment(t)
				// Keep the SDK from burning retries on a deterministic failure.
				t.Setenv("AWS_MAX_ATTEMPTS", "1")
				t.Setenv("AWS_REGION", "us-east-1")

				stsRec := newSTSRecorder(t, http.StatusForbidden,
					stsErrorResponse(stsErr.code, stsErr.message))

				spec := &secretsv1beta1.VaultAuthConfigAWS{
					Role:        "vso-vault-role",
					Region:      "us-east-1",
					STSEndpoint: stsRec.URL,
				}

				var client ctrlclient.Client
				if path.irsa {
					spec.IRSAServiceAccount = "vso-irsa-sa"
					sa := newIRSAServiceAccount("vso-irsa-sa", namespace,
						"arn:aws:iam::123456789012:role/vso-irsa-role", nil)
					client = withTokenRequests(newFakeClient(t, sa), "irsa-sa-token", nil, nil).Build()
				} else {
					imds := &fakeIMDS{}
					t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds.start(t).URL)
					// Picked up by awsutil.NewCredentialsConfig; VSO has no
					// spec field for the assumed role on this path.
					t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/vso-target-role")
					client = newFakeClient(t, kubeRootCAConfigMap()).Build()
				}

				authObj := &secretsv1beta1.VaultAuth{
					ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
					Spec:       secretsv1beta1.VaultAuthSpec{Method: "aws", AWS: spec},
				}

				ctx := context.Background()
				provider := &AWSCredentialProvider{}
				require.NoError(t, provider.Init(ctx, client, authObj, namespace))

				loginData, err := provider.GetCreds(ctx, client)
				require.Error(t, err,
					"a rejected STS call must fail the login rather than silently "+
						"falling back to the source credentials")
				assert.Nil(t, loginData,
					"no login data may be returned when credentials could not be retrieved")
				assert.Contains(t, err.Error(), stsErr.code,
					"the underlying STS error code should reach the caller")
				assert.NotEmpty(t, stsRec.Calls(), "expected the flow to actually call STS")

				if !path.irsa {
					assert.NotContains(t, err.Error(), nodeAccessKeyID,
						"node credentials must not be used to sign the login request")
				}
			})
		}
	}
}
