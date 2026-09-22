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

func Test_buildSignedGetCallerIdentityRequest(t *testing.T) {
	ctx := context.Background()

	// Minimal fake credentials — just need to be structurally valid for signing.
	creds := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}

	endpoint := stsSigningEndpoint{
		requestURL:    "https://sts.us-east-1.amazonaws.com",
		signingName:   stsSigningName,
		signingRegion: "us-east-1",
	}

	t.Run("produces correct method and body", func(t *testing.T) {
		req, body, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "")
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, stsGetCallerIdentityBody, body)
		assert.Equal(t, stsContentType, req.Header.Get("Content-Type"))
	})

	t.Run("sets X-Vault-AWS-IAM-Server-ID header when provided", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "vault.example.com")
		require.NoError(t, err)
		assert.Equal(t, "vault.example.com", req.Header.Get(iamServerIDHeader))
	})

	t.Run("does not set X-Vault-AWS-IAM-Server-ID when empty", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "")
		require.NoError(t, err)
		assert.Empty(t, req.Header.Get(iamServerIDHeader))
	})

	t.Run("request is signed (Authorization header present)", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "")
		require.NoError(t, err)
		assert.NotEmpty(t, req.Header.Get("Authorization"), "signed request must have Authorization header")
		assert.Contains(t, req.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
	})

	t.Run("request URL matches endpoint", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "")
		require.NoError(t, err)
		assert.Equal(t, "https://sts.us-east-1.amazonaws.com", req.URL.String())
	})

	t.Run("temporary credentials with SessionToken produce X-Amz-Security-Token header", func(t *testing.T) {
		tempCreds := aws.Credentials{
			AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "AQoXnyc4lcK4w=",
			Source:          "test",
		}
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, tempCreds, endpoint, "")
		require.NoError(t, err)
		// AWS SDK v4 signer writes the session token as X-Amz-Security-Token.
		assert.NotEmpty(t, req.Header.Get("X-Amz-Security-Token"),
			"signed request with SessionToken must include X-Amz-Security-Token header")
		assert.Equal(t, "AQoXnyc4lcK4w=", req.Header.Get("X-Amz-Security-Token"))
	})
}

func Test_generateLoginData(t *testing.T) {
	ctx := context.Background()

	staticCreds := aws.Credentials{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Source:          "test",
	}
	awsCfg := &aws.Config{
		Region:      "us-east-1",
		Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: staticCreds}),
	}

	t.Run("nil config returns error", func(t *testing.T) {
		_, err := generateLoginData(ctx, nil, "", "")
		require.ErrorContains(t, err, "AWS credentials are not configured")
	})

	t.Run("config with nil Credentials returns error", func(t *testing.T) {
		_, err := generateLoginData(ctx, &aws.Config{}, "", "")
		require.ErrorContains(t, err, "AWS credentials are not configured")
	})

	t.Run("empty credentials return error", func(t *testing.T) {
		emptyCfg := &aws.Config{
			Region:      "us-east-1",
			Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: aws.Credentials{}}),
		}
		_, err := generateLoginData(ctx, emptyCfg, "", "")
		require.ErrorContains(t, err, "retrieved AWS credentials are empty")
	})

	t.Run("temporary credentials with SessionToken include X-Amz-Security-Token in headers", func(t *testing.T) {
		tempCreds := aws.Credentials{
			AccessKeyID:     "ASIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			SessionToken:    "AQoXnyc4lcK4w=",
			Source:          "test",
		}
		tempCfg := &aws.Config{
			Region:      "us-east-1",
			Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: tempCreds}),
		}
		loginData, err := generateLoginData(ctx, tempCfg, "", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
		require.NoError(t, err)
		var headers map[string][]string
		require.NoError(t, json.Unmarshal(decoded, &headers))
		vals, ok := headers["X-Amz-Security-Token"]
		require.True(t, ok, "X-Amz-Security-Token must be present for temporary credentials")
		assert.Equal(t, "AQoXnyc4lcK4w=", vals[0])
	})

	t.Run("produces all required login data keys", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "")
		require.NoError(t, err)

		for _, key := range []string{
			"iam_http_request_method",
			"iam_request_url",
			"iam_request_headers",
			"iam_request_body",
		} {
			assert.Contains(t, loginData, key, "missing key: %s", key)
		}
	})

	t.Run("iam_http_request_method is POST", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "")
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, loginData["iam_http_request_method"])
	})

	t.Run("iam_request_url is base64 encoded STS URL", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_url"].(string))
		require.NoError(t, err)
		assert.Contains(t, string(decoded), "sts.us-east-1.amazonaws.com")
	})

	t.Run("iam_request_body is base64 encoded GetCallerIdentity body", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_body"].(string))
		require.NoError(t, err)
		assert.Equal(t, stsGetCallerIdentityBody, string(decoded))
	})

	t.Run("iam_request_headers is valid base64 JSON with Authorization", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
		require.NoError(t, err)
		var headers map[string]interface{}
		require.NoError(t, json.Unmarshal(decoded, &headers))
		_, hasAuth := headers["Authorization"]
		assert.True(t, hasAuth, "headers should contain Authorization")
	})

	t.Run("header value is included in headers", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "vault.example.com", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
		require.NoError(t, err)
		var headers map[string][]string
		require.NoError(t, json.Unmarshal(decoded, &headers))
		// http.Header canonicalizes keys: "X-Vault-AWS-IAM-Server-ID" → "X-Vault-Aws-Iam-Server-Id"
		canonicalKey := http.CanonicalHeaderKey(iamServerIDHeader)
		vals, ok := headers[canonicalKey]
		require.True(t, ok, "header %q should be present (canonical: %q)", iamServerIDHeader, canonicalKey)
		assert.Equal(t, "vault.example.com", vals[0])
	})

	t.Run("custom STS endpoint is used when provided", func(t *testing.T) {
		loginData, err := generateLoginData(ctx, awsCfg, "", "https://localstack:4566")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_url"].(string))
		require.NoError(t, err)
		assert.Contains(t, string(decoded), "localstack:4566")
	})

	t.Run("falls back to DefaultRegion when config region is empty", func(t *testing.T) {
		noRegionCfg := &aws.Config{
			Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: staticCreds}),
		}
		loginData, err := generateLoginData(ctx, noRegionCfg, "", "")
		require.NoError(t, err)
		decoded, err := base64.StdEncoding.DecodeString(loginData["iam_request_url"].(string))
		require.NoError(t, err)
		assert.Contains(t, string(decoded), awsutil.DefaultRegion)
	})

	t.Run("config region determines the SigV4 credential scope", func(t *testing.T) {
		// The region only matters if it reaches the signature. A login signed
		// under the wrong regional scope is rejected by STS, so assert on the
		// Authorization header rather than on the request URL alone.
		regionalCfg := &aws.Config{
			Region:      "eu-west-1",
			Credentials: aws.NewCredentialsCache(staticCredentialsProvider{creds: staticCreds}),
		}
		loginData, err := generateLoginData(ctx, regionalCfg, "", "")
		require.NoError(t, err)

		rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
		require.NoError(t, err)
		var headers map[string][]string
		require.NoError(t, json.Unmarshal(rawHeaders, &headers))
		require.NotEmpty(t, headers["Authorization"])

		assert.Contains(t, headers["Authorization"][0], "/eu-west-1/sts/aws4_request",
			"the configured region must appear in the SigV4 credential scope")
		assert.NotContains(t, headers["Authorization"][0], awsutil.DefaultRegion)
	})
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

// Test_applyCredentialsOverride_AssumeRoleForNodeRoleFlow isolates the override
// on the node-role path: with RoleARN set and no web identity token it must
// install an assume-role provider that sources its credentials from the
// existing chain (EC2 IMDS) and calls sts:AssumeRole through the configured
// STSEndpointResolver.
func Test_applyCredentialsOverride_AssumeRoleForNodeRoleFlow(t *testing.T) {
	isolateAWSEnvironment(t)

	imds := &fakeIMDS{}
	imdsServer := imds.start(t)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)
	t.Setenv("AWS_REGION", "us-east-1")

	var mu sync.Mutex
	var stsCalls []url.Values
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		mu.Lock()
		stsCalls = append(stsCalls, r.PostForm)
		mu.Unlock()

		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(assumeRoleResponse))
	}))
	defer stsServer.Close()

	stsURL, err := url.Parse(stsServer.URL)
	require.NoError(t, err)

	cfg, err := awsutil.NewCredentialsConfig()
	require.NoError(t, err)
	cfg.Region = "us-east-1"
	cfg.RoleARN = "arn:aws:iam::123456789012:role/vso-target-role"
	cfg.RoleExternalId = "external-id-123"
	cfg.RoleTags = map[string]string{"team": "vso", "env": "test"}
	cfg.STSEndpointResolver = stsEndpointResolverFunc(func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
		return smithyendpoints.Endpoint{URI: *stsURL}, nil
	})
	// Deliberately no WebIdentityToken / WebIdentityTokenFile.

	awsCfg, err := cfg.GenerateCredentialChain(context.Background())
	require.NoError(t, err)

	before := awsCfg.Credentials
	applyCredentialsOverride(awsCfg, cfg, nil, "")
	assert.NotSame(t, before, awsCfg.Credentials,
		"override must install an assume-role provider on the node-role path")

	creds, err := awsCfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "AKIAASSUMEDROLE", creds.AccessKeyID,
		"the chain must resolve to assumed-role credentials, not node credentials")

	mu.Lock()
	calls := append([]url.Values(nil), stsCalls...)
	mu.Unlock()

	require.Len(t, calls, 1)
	assert.Equal(t, "AssumeRole", calls[0].Get("Action"))
	assert.Equal(t, "external-id-123", calls[0].Get("ExternalId"),
		"RoleExternalId must be propagated")
	// Tags are sorted by key: env, team.
	assert.Equal(t, "env", calls[0].Get("Tags.member.1.Key"))
	assert.Equal(t, "test", calls[0].Get("Tags.member.1.Value"))
	assert.Equal(t, "team", calls[0].Get("Tags.member.2.Key"))
	assert.Equal(t, "vso", calls[0].Get("Tags.member.2.Value"))
}

// Test_applyCredentialsOverride_PreservesCredentialPrecedence asserts that the
// role-assumption override never outranks credentials the AWS credential chain
// legitimately selected.
//
// When VSO itself runs on EKS under IRSA, the operator pod carries AWS_ROLE_ARN
// and AWS_WEB_IDENTITY_TOKEN_FILE. awsutil.NewCredentialsConfig() seeds
// CredentialsConfig.RoleARN from AWS_ROLE_ARN, so a VaultAuth that never asked
// for role assumption can still present a non-empty RoleARN inherited from the
// operator's own environment. Acting on that inherited value would sign the
// Vault login request as the operator's role instead of the identity the
// VaultAuth configured.
//
// Each case asserts *which* credentials would sign the login request, by access
// key ID, rather than merely that credential resolution succeeded.
func Test_applyCredentialsOverride_PreservesCredentialPrecedence(t *testing.T) {
	const (
		operatorRoleARN  = "arn:aws:iam::123456789012:role/operator-irsa-role"
		secretAccessKey  = "AKIAFROMSECRET"
		envAccessKeyID   = "AKIAFROMENV"
		sharedAccessKeyI = "AKIAFROMPROFILE"
	)

	makeProvider := func(spec *secretsv1beta1.VaultAuthConfigAWS) *AWSCredentialProvider {
		return &AWSCredentialProvider{
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{AWS: spec},
			},
		}
	}

	// simulateOperatorIRSAPod sets the environment variables present in an
	// IRSA-enabled operator pod.
	simulateOperatorIRSAPod := func(t *testing.T) {
		t.Helper()
		tokenFile := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(tokenFile, []byte("operator-pod-jwt"), 0o600))
		t.Setenv("AWS_ROLE_ARN", operatorRoleARN)
		t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	}

	t.Run("secretRef credentials survive an inherited AWS_ROLE_ARN", func(t *testing.T) {
		isolateAWSEnvironment(t)
		simulateOperatorIRSAPod(t)

		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "us-east-1"})
		credsSecret := &corev1.Secret{
			Data: map[string][]byte{
				consts.AWSAccessKeyID:     []byte(secretAccessKey),
				consts.AWSSecretAccessKey: []byte("secretFromK8sSecret"),
			},
		}
		// secretRef flow: GetCreds supplies the Secret and no IRSA config.
		cfg, err := p.getCredentialsConfig(credsSecret, nil, "")
		require.NoError(t, err)
		require.Equal(t, operatorRoleARN, cfg.RoleARN,
			"precondition: awsutil seeds RoleARN from the operator pod's environment")

		awsCfg, err := cfg.GenerateCredentialChain(context.Background())
		require.NoError(t, err)

		before, err := awsCfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err)
		require.Equal(t, secretAccessKey, before.AccessKeyID,
			"precondition: the chain selects the Secret's static credentials")

		applyCredentialsOverride(awsCfg, cfg, nil, "")

		after, err := awsCfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err, "override must not break credential retrieval")
		assert.Equal(t, secretAccessKey, after.AccessKeyID,
			"the Vault login request must still be signed with the secretRef credentials, "+
				"not the operator's inherited IRSA role")
	})

	t.Run("environment credentials survive an inherited AWS_ROLE_ARN", func(t *testing.T) {
		isolateAWSEnvironment(t)
		simulateOperatorIRSAPod(t)
		t.Setenv("AWS_ACCESS_KEY_ID", envAccessKeyID)
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secretFromEnv")

		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "us-east-1"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)

		awsCfg, err := cfg.GenerateCredentialChain(context.Background())
		require.NoError(t, err)

		applyCredentialsOverride(awsCfg, cfg, nil, "")

		after, err := awsCfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err, "override must not break credential retrieval")
		assert.Equal(t, envAccessKeyID, after.AccessKeyID,
			"the Vault login request must still be signed with the environment credentials")
	})

	t.Run("override stands down whenever the chain resolved static credentials", func(t *testing.T) {
		isolateAWSEnvironment(t)
		simulateOperatorIRSAPod(t)

		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "us-east-1"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)

		awsCfg, err := cfg.GenerateCredentialChain(context.Background())
		require.NoError(t, err)

		// Stand in for any static-credential source the chain may settle on -
		// secretRef, the environment, or a shared profile all resolve to a
		// credentials.StaticCredentialsProvider.
		awsCfg.Credentials = aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider(sharedAccessKeyI, "secretFromProfile", ""))
		require.True(t, resolvedStaticCredentials(awsCfg.Credentials),
			"precondition: the guard recognizes static credentials")

		before := awsCfg.Credentials
		applyCredentialsOverride(awsCfg, cfg, nil, "")
		assert.Same(t, before, awsCfg.Credentials,
			"override must leave static credentials untouched")

		after, err := awsCfg.Credentials.Retrieve(context.Background())
		require.NoError(t, err)
		assert.Equal(t, sharedAccessKeyI, after.AccessKeyID)
	})

	t.Run("explicit irsaServiceAccount outranks ambient static credentials", func(t *testing.T) {
		isolateAWSEnvironment(t)
		// Ambient static credentials that must NOT win, because the VaultAuth
		// explicitly named an irsaServiceAccount.
		t.Setenv("AWS_ACCESS_KEY_ID", envAccessKeyID)
		t.Setenv("AWS_SECRET_ACCESS_KEY", "secretFromEnv")

		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{
			Role:               "r",
			Region:             "us-east-1",
			IRSAServiceAccount: "irsa-sa",
		})
		irsa := &IRSAConfig{RoleARN: "arn:aws:iam::123456789012:role/vaultauth-irsa-role"}
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, irsa, "vaultauth-sa-jwt")
		require.NoError(t, err)

		awsCfg, err := cfg.GenerateCredentialChain(context.Background())
		require.NoError(t, err)

		applyCredentialsOverride(awsCfg, cfg, irsa, "vaultauth-sa-jwt")

		assert.False(t, resolvedStaticCredentials(awsCfg.Credentials),
			"an explicit irsaServiceAccount must install a role provider, "+
				"not fall back to ambient static credentials")
	})
}

// stsEndpointResolverFunc adapts a function to sts.EndpointResolverV2 so tests
// can point the SDK at a local httptest server.
type stsEndpointResolverFunc func(context.Context, sts.EndpointParameters) (smithyendpoints.Endpoint, error)

func (f stsEndpointResolverFunc) ResolveEndpoint(ctx context.Context, params sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return f(ctx, params)
}

// ─── endpoint resolvers, helpers ───

// Test_customSTSEndpointResolver covers the resolver installed by
// getCredentialsConfig when spec.aws.stsEndpoint is set, including the
// malformed-URL path.
func Test_customSTSEndpointResolver(t *testing.T) {
	t.Run("resolves the configured endpoint", func(t *testing.T) {
		r := &customSTSEndpointResolver{endpointURL: "https://sts.example.internal:8443/path"}
		ep, err := r.ResolveEndpoint(context.Background(), sts.EndpointParameters{})
		require.NoError(t, err)
		assert.Equal(t, "https://sts.example.internal:8443/path", ep.URI.String())
	})

	t.Run("ignores the region when a custom endpoint is configured", func(t *testing.T) {
		r := &customSTSEndpointResolver{endpointURL: "https://sts.example.internal"}
		ep, err := r.ResolveEndpoint(context.Background(), sts.EndpointParameters{
			Region: aws.String("eu-west-1"),
		})
		require.NoError(t, err)
		assert.Equal(t, "https://sts.example.internal", ep.URI.String())
	})

	t.Run("returns an error for a malformed URL", func(t *testing.T) {
		r := &customSTSEndpointResolver{endpointURL: "http://[::1]:namedport"}
		_, err := r.ResolveEndpoint(context.Background(), sts.EndpointParameters{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse custom STS endpoint URL")
	})
}

// Test_customIAMEndpointResolver covers the resolver installed by
// getCredentialsConfig when spec.aws.iamEndpoint is set.
func Test_customIAMEndpointResolver(t *testing.T) {
	t.Run("resolves the configured endpoint", func(t *testing.T) {
		r := &customIAMEndpointResolver{endpointURL: "https://iam.example.internal"}
		ep, err := r.ResolveEndpoint(context.Background(), iam.EndpointParameters{})
		require.NoError(t, err)
		assert.Equal(t, "https://iam.example.internal", ep.URI.String())
	})

	t.Run("returns an error for a malformed URL", func(t *testing.T) {
		r := &customIAMEndpointResolver{endpointURL: "http://[::1]:namedport"}
		_, err := r.ResolveEndpoint(context.Background(), iam.EndpointParameters{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse custom IAM endpoint URL")
	})
}

// Test_sortedKeys guards the deterministic ordering that applyCredentialsOverride
// relies on when translating RoleTags into sts:AssumeRole Tags.member.N entries.
func Test_sortedKeys(t *testing.T) {
	assert.Equal(t, []string{"a", "b", "z"}, sortedKeys(map[string]string{"z": "1", "a": "2", "b": "3"}))
	assert.Empty(t, sortedKeys(map[string]string{}))
	assert.Empty(t, sortedKeys(nil))
}

// Test_resolvedStaticCredentials covers the guard that keeps
// applyCredentialsOverride from outranking credentials the AWS credential chain
// already selected.
func Test_resolvedStaticCredentials(t *testing.T) {
	t.Run("true for a cached static provider", func(t *testing.T) {
		provider := aws.NewCredentialsCache(
			credentials.NewStaticCredentialsProvider("AKIA", "secret", ""))
		assert.True(t, resolvedStaticCredentials(provider))
	})

	t.Run("true for a bare static provider", func(t *testing.T) {
		assert.True(t, resolvedStaticCredentials(
			credentials.NewStaticCredentialsProvider("AKIA", "secret", "")))
	})

	t.Run("false for a non-static provider", func(t *testing.T) {
		provider := aws.NewCredentialsCache(staticCredentialsProvider{
			creds: aws.Credentials{AccessKeyID: "AKIA", SecretAccessKey: "secret"},
		})
		assert.False(t, resolvedStaticCredentials(provider),
			"only credentials.StaticCredentialsProvider should be treated as static")
	})

	t.Run("false for nil", func(t *testing.T) {
		assert.False(t, resolvedStaticCredentials(nil))
	})
}

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

// newIRSAFakeClient builds a fake client holding an IRSA-annotated
// ServiceAccount whose TokenRequest subresource mints the supplied token.
func newIRSAFakeClient(t *testing.T, namespace, saName, roleARN, token string) ctrlclient.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:        saName,
			Namespace:   namespace,
			UID:         "sa-uid",
			Annotations: map[string]string{AWSAnnotationRole: roleARN},
		},
	}

	return fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(sa).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceCreate: func(ctx context.Context, c ctrlclient.Client, subResourceName string, obj ctrlclient.Object, subResource ctrlclient.Object, opts ...ctrlclient.SubResourceCreateOption) error {
				tr, ok := subResource.(*authenticationv1.TokenRequest)
				if !ok || subResourceName != "token" {
					return c.SubResource(subResourceName).Create(ctx, obj, subResource, opts...)
				}
				tr.Status.Token = token
				return nil
			},
		}).
		Build()
}

// newNodeRoleFakeClient builds a fake client containing the kube-root-ca.crt
// ConfigMap that Init requires on the node-role/instance-profile path.
func newNodeRoleFakeClient(t *testing.T) ctrlclient.Client {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	rootCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      K8sRootCA,
			Namespace: common.OperatorNamespace,
			UID:       "root-ca-uid",
		},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(rootCA).Build()
}

// Test_GetCreds_STSErrorPropagates asserts that an STS failure during credential
// retrieval surfaces as a non-nil error from GetCreds on both the IRSA and
// node-role paths.
//
// This is the guard against a silent fallback. Both paths replace the credential
// chain with a role provider that resolves lazily, so a rejected AssumeRole or
// AssumeRoleWithWebIdentity must abort the login rather than quietly signing it
// with whatever credentials the chain resolved earlier (node credentials, or an
// ambient identity). Returning login data here would authenticate to Vault as
// the wrong principal.
func Test_GetCreds_STSErrorPropagates(t *testing.T) {
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

	// newFailingSTS serves the given STS error and counts the requests it saw.
	newFailingSTS := func(t *testing.T, code, message string, calls *int32) *httptest.Server {
		t.Helper()
		var mu sync.Mutex
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			*calls++
			mu.Unlock()
			w.Header().Set("Content-Type", "text/xml")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(stsErrorResponse(code, message)))
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	for name, stsErr := range stsErrors {
		t.Run("IRSA path returns an error on "+name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			// Keep the SDK from burning retries on a deterministic failure.
			t.Setenv("AWS_MAX_ATTEMPTS", "1")
			t.Setenv("AWS_REGION", "us-east-1")

			const namespace = "vso-test-ns"
			var stsCalls int32
			stsServer := newFailingSTS(t, stsErr.code, stsErr.message, &stsCalls)

			client := newIRSAFakeClient(t, namespace, "vso-irsa-sa",
				"arn:aws:iam::123456789012:role/vso-irsa-role", "irsa-sa-token")

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:               "vso-vault-role",
						Region:             "us-east-1",
						STSEndpoint:        stsServer.URL,
						IRSAServiceAccount: "vso-irsa-sa",
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, namespace))

			loginData, err := provider.GetCreds(ctx, client)
			require.Error(t, err, "a rejected AssumeRoleWithWebIdentity must fail the login")
			assert.Nil(t, loginData, "no login data may be returned when credentials could not be retrieved")
			assert.Contains(t, err.Error(), stsErr.code,
				"the underlying STS error code should reach the caller")
			assert.Positive(t, stsCalls, "expected the IRSA path to actually call STS")
		})

		t.Run("node role path returns an error on "+name, func(t *testing.T) {
			isolateAWSEnvironment(t)
			t.Setenv("AWS_MAX_ATTEMPTS", "1")
			t.Setenv("AWS_REGION", "us-east-1")

			imds := &fakeIMDS{}
			imdsServer := imds.start(t)
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)
			// Picked up by awsutil.NewCredentialsConfig; VSO has no spec field
			// for the assumed role on this path.
			t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/vso-target-role")

			var stsCalls int32
			stsServer := newFailingSTS(t, stsErr.code, stsErr.message, &stsCalls)

			client := newNodeRoleFakeClient(t)

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: "vso-test-ns"},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						STSEndpoint: stsServer.URL,
					},
				},
			}

			ctx := context.Background()
			provider := &AWSCredentialProvider{}
			require.NoError(t, provider.Init(ctx, client, authObj, "vso-test-ns"))

			loginData, err := provider.GetCreds(ctx, client)
			require.Error(t, err, "a rejected AssumeRole must fail the login rather than "+
				"silently falling back to the node credentials")
			assert.Nil(t, loginData, "no login data may be returned when credentials could not be retrieved")
			assert.Contains(t, err.Error(), stsErr.code,
				"the underlying STS error code should reach the caller")
			assert.Positive(t, stsCalls, "expected the node-role path to actually call STS")
			assert.NotContains(t, err.Error(), nodeAccessKeyID,
				"node credentials must not be used to sign the login request")
		})
	}
}

// Test_applyCredentialsOverride_AssumesTheValidatedRole guards against the
// decision and the action drifting apart.
//
// applyCredentialsOverride decides that an explicit IRSA request is in play by
// inspecting irsaConfig.RoleARN, but the role it assumes must be that same
// value. credsConfig.RoleARN normally carries it too, yet that field is also
// what awsutil seeds from the operator pod's own AWS_ROLE_ARN. If the two ever
// diverge, assuming the credsConfig value would authenticate to Vault as a role
// the VaultAuth never asked for.
func Test_applyCredentialsOverride_AssumesTheValidatedRole(t *testing.T) {
	isolateAWSEnvironment(t)
	t.Setenv("AWS_REGION", "us-east-1")

	const (
		vaultAuthRoleARN = "arn:aws:iam::123456789012:role/vaultauth-requested-role"
		operatorRoleARN  = "arn:aws:iam::999999999999:role/operator-inherited-role"
		irsaToken        = "vaultauth-sa-jwt"
	)

	var mu sync.Mutex
	var stsCalls []url.Values
	stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		mu.Lock()
		stsCalls = append(stsCalls, r.PostForm)
		mu.Unlock()
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte(assumeRoleWithWebIdentityResponse))
	}))
	defer stsServer.Close()
	stsURL, err := url.Parse(stsServer.URL)
	require.NoError(t, err)

	cfg, err := awsutil.NewCredentialsConfig()
	require.NoError(t, err)
	cfg.Region = "us-east-1"
	// Simulate the two sources disagreeing: credsConfig holds the operator's
	// inherited role while the VaultAuth asked for a different one.
	cfg.RoleARN = operatorRoleARN
	cfg.WebIdentityToken = irsaToken
	cfg.STSEndpointResolver = stsEndpointResolverFunc(
		func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
			return smithyendpoints.Endpoint{URI: *stsURL}, nil
		})

	awsCfg, err := cfg.GenerateCredentialChain(context.Background())
	require.NoError(t, err)

	applyCredentialsOverride(awsCfg, cfg, &IRSAConfig{RoleARN: vaultAuthRoleARN}, irsaToken)

	_, err = awsCfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)

	mu.Lock()
	calls := append([]url.Values(nil), stsCalls...)
	mu.Unlock()

	require.Len(t, calls, 1)
	assert.Equal(t, vaultAuthRoleARN, calls[0].Get("RoleArn"),
		"must assume the role the VaultAuth asked for, not the one inherited from the operator environment")
	assert.NotEqual(t, operatorRoleARN, calls[0].Get("RoleArn"))
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
		check      func(t *testing.T, cfg *awsutil.CredentialsConfig)
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
			var imdsHits []string
			imds := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				imdsHits = append(imdsHits, r.URL.Path)
				mu.Unlock()
				http.Error(w, "no instance role available", http.StatusNotFound)
			}))
			defer imds.Close()
			t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imds.URL)

			var stsCalls []url.Values
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				stsCalls = append(stsCalls, r.PostForm)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(assumeRoleWithWebIdentityResponse))
			}))
			defer stsServer.Close()

			sa := &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name: saName, Namespace: namespace, UID: "sa-uid",
					Annotations: tt.annotations,
				},
			}

			scheme := runtime.NewScheme()
			require.NoError(t, clientgoscheme.AddToScheme(scheme))
			require.NoError(t, secretsv1beta1.AddToScheme(scheme))

			var tokenRequests []authenticationv1.TokenRequestSpec
			client := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(sa).
				WithInterceptorFuncs(interceptor.Funcs{
					SubResourceCreate: func(ctx context.Context, c ctrlclient.Client, subResourceName string, obj, subResource ctrlclient.Object, opts ...ctrlclient.SubResourceCreateOption) error {
						tr, ok := subResource.(*authenticationv1.TokenRequest)
						if !ok || subResourceName != "token" {
							return c.SubResource(subResourceName).Create(ctx, obj, subResource, opts...)
						}
						mu.Lock()
						tokenRequests = append(tokenRequests, tr.Spec)
						mu.Unlock()
						tr.Status.Token = saToken
						return nil
					},
				}).
				Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:               vaultRole,
						Region:             "us-east-1",
						SessionName:        tt.sessionName,
						STSEndpoint:        stsServer.URL,
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

			require.Empty(t, imdsHits,
				"VSO must not fall back to EC2 instance metadata / node credentials when irsaServiceAccount is configured")

			// The ServiceAccount token was requested with the annotation-derived
			// audience and expiration.
			require.Len(t, tokenRequests, 1, "expected exactly one ServiceAccount TokenRequest")
			assert.Equal(t, []string{tt.expectedAudience}, tokenRequests[0].Audiences)
			require.NotNil(t, tokenRequests[0].ExpirationSeconds)
			assert.Equal(t, tt.expectedExpiration, *tokenRequests[0].ExpirationSeconds)

			// Credential retrieval went through the configured stsEndpoint and
			// presented the VaultAuth's own token and role.
			require.Len(t, stsCalls, 1, "expected exactly one STS call")
			call := stsCalls[0]
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

			rawURL, err := base64.StdEncoding.DecodeString(loginData["iam_request_url"].(string))
			require.NoError(t, err)
			loginURL, err := url.Parse(string(rawURL))
			require.NoError(t, err)
			stsURL, err := url.Parse(stsServer.URL)
			require.NoError(t, err)
			assert.Equal(t, stsURL.Host, loginURL.Host,
				"login request must target the configured STS endpoint")

			rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
			require.NoError(t, err)
			var headers map[string][]string
			require.NoError(t, json.Unmarshal(rawHeaders, &headers))
			require.NotEmpty(t, headers["Authorization"])
			assert.Contains(t, headers["Authorization"][0], assumedKeyID,
				"login request must be signed with the web identity credentials")
			assert.Equal(t, []string{assumedToken}, headers["X-Amz-Security-Token"])
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

			var mu sync.Mutex
			var stsCalls []url.Values
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				mu.Lock()
				stsCalls = append(stsCalls, r.PostForm)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/xml")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(assumeRoleResponse))
			}))
			defer stsServer.Close()

			client := newNodeRoleFakeClient(t)

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: "vso-test-ns"},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						SessionName: sessionName,
						STSEndpoint: stsServer.URL,
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

			mu.Lock()
			calls := append([]url.Values(nil), stsCalls...)
			mu.Unlock()

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

			rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
			require.NoError(t, err)
			var headers map[string][]string
			require.NoError(t, json.Unmarshal(rawHeaders, &headers))
			require.NotEmpty(t, headers["Authorization"])
			authHeader := headers["Authorization"][0]

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

			var mu sync.Mutex
			var stsCalls []url.Values
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, r.ParseForm())
				mu.Lock()
				stsCalls = append(stsCalls, r.PostForm)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(assumeRoleWithWebIdentityResponse))
			}))
			defer stsServer.Close()
			stsURL, err := url.Parse(stsServer.URL)
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

			mu.Lock()
			calls := append([]url.Values(nil), stsCalls...)
			mu.Unlock()

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
			var mu sync.Mutex
			var stsCalls []url.Values
			stsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = r.ParseForm()
				mu.Lock()
				stsCalls = append(stsCalls, r.PostForm)
				mu.Unlock()
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte(assumeRoleWithWebIdentityResponse))
			}))
			defer stsServer.Close()

			scheme := runtime.NewScheme()
			require.NoError(t, clientgoscheme.AddToScheme(scheme))
			require.NoError(t, secretsv1beta1.AddToScheme(scheme))

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
			client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(credsSecret).Build()

			authObj := &secretsv1beta1.VaultAuth{
				ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
				Spec: secretsv1beta1.VaultAuthSpec{
					Method: "aws",
					AWS: &secretsv1beta1.VaultAuthConfigAWS{
						Role:        "vso-vault-role",
						Region:      "us-east-1",
						STSEndpoint: stsServer.URL,
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

			mu.Lock()
			calls := append([]url.Values(nil), stsCalls...)
			mu.Unlock()
			assert.Empty(t, calls,
				"static credentials require no STS call; any call means a role was wrongly assumed")

			rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
			require.NoError(t, err)
			var headers map[string][]string
			require.NoError(t, json.Unmarshal(rawHeaders, &headers))
			require.NotEmpty(t, headers["Authorization"])

			assert.Contains(t, headers["Authorization"][0], accessKey,
				"the Vault login must be signed with the Secret's credentials")
			assert.NotContains(t, headers["Authorization"][0], "AKIAIRSAONLY",
				"the Vault login must not be signed with assumed-role credentials")
			assert.Equal(t, []string{sessToken}, headers["X-Amz-Security-Token"])
			assert.Equal(t, "vso-vault-role", loginData["role"])
		})
	}
}
