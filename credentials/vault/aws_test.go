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
}

func Test_getCredentialsConfig(t *testing.T) {
	makeProvider := func(spec *secretsv1beta1.VaultAuthConfigAWS) *AWSCredentialProvider {
		return &AWSCredentialProvider{
			authObj: &secretsv1beta1.VaultAuth{
				Spec: secretsv1beta1.VaultAuthSpec{
					AWS: spec,
				},
			},
		}
	}

	t.Run("sets Region from spec", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", Region: "eu-west-1"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)
		assert.Equal(t, "eu-west-1", cfg.Region)
	})

	t.Run("sets RoleSessionName from spec", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", SessionName: "my-session"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)
		assert.Equal(t, "my-session", cfg.RoleSessionName)
	})

	t.Run("sets STSEndpointResolver when STSEndpoint specified", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", STSEndpoint: "https://sts.local"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)
		assert.NotNil(t, cfg.STSEndpointResolver)
	})

	t.Run("STSEndpointResolver is nil when STSEndpoint not specified", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)
		assert.Nil(t, cfg.STSEndpointResolver)
	})

	t.Run("sets IAMEndpointResolver when IAMEndpoint specified", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r", IAMEndpoint: "https://iam.local"})
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, nil, "")
		require.NoError(t, err)
		assert.NotNil(t, cfg.IAMEndpointResolver)
	})

	t.Run("reads static creds from secret", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r"})
		secret := &corev1.Secret{
			Data: map[string][]byte{
				consts.AWSAccessKeyID:     []byte("AKID"),
				consts.AWSSecretAccessKey: []byte("SECRET"),
				consts.AWSSessionToken:    []byte("TOKEN"),
			},
		}
		cfg, err := p.getCredentialsConfig(secret, nil, "")
		require.NoError(t, err)
		assert.Equal(t, "AKID", cfg.AccessKey)
		assert.Equal(t, "SECRET", cfg.SecretKey)
		assert.Equal(t, "TOKEN", cfg.SessionToken)
	})

	t.Run("sets RoleARN from IRSAConfig", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r"})
		irsa := &IRSAConfig{RoleARN: "arn:aws:iam::123:role/test"}
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, irsa, "")
		require.NoError(t, err)
		assert.Equal(t, "arn:aws:iam::123:role/test", cfg.RoleARN)
	})

	t.Run("sets WebIdentityToken when IRSA token provided", func(t *testing.T) {
		p := makeProvider(&secretsv1beta1.VaultAuthConfigAWS{Role: "r"})
		irsa := &IRSAConfig{RoleARN: "arn:aws:iam::123:role/test"}
		cfg, err := p.getCredentialsConfig(&corev1.Secret{}, irsa, "my-token")
		require.NoError(t, err)
		assert.Equal(t, "my-token", cfg.WebIdentityToken)
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

// ─── from aws_irsa_test.go ───

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

// Test_GetCreds_IRSAOnly_UsesAssumeRoleWithWebIdentity exercises the full
// AWSCredentialProvider.GetCreds path with irsaServiceAccount as the *only*
// configured credential source: no secretRef, no static credentials, no
// AWS_WEB_IDENTITY_TOKEN_FILE/AWS_ROLE_ARN environment variables, no shared
// profile, and an EC2 instance metadata service that refuses to hand out node
// credentials.
//
// It asserts that VSO assumes the annotated role by calling
// sts:AssumeRoleWithWebIdentity with the ServiceAccount token obtained from the
// Kubernetes TokenRequest API, and that it never falls back to node
// credentials. Without applyCredentialsOverride this fails: awsutil
// passes the inline token via config.WithWebIdentityRoleCredentialOptions,
// which the SDK only applies to a WebIdentityRoleProvider it has already
// decided to build from AWS_WEB_IDENTITY_TOKEN_FILE, so the chain silently
// falls through to the IMDS provider.
func Test_GetCreds_IRSAOnly_UsesAssumeRoleWithWebIdentity(t *testing.T) {
	isolateAWSEnvironment(t)

	const (
		roleARN     = "arn:aws:iam::123456789012:role/vso-irsa-role"
		audience    = "vso.test.audience"
		sessionName = "vso-session"
		saName      = "vso-irsa-sa"
		namespace   = "vso-test-ns"
		saToken     = "header.irsa-service-account-token.signature"
	)

	// Stand in for the EC2 instance metadata service, recording any attempt to
	// fall back to node credentials and refusing to supply them.
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
			Name:      saName,
			Namespace: namespace,
			UID:       "sa-uid",
			Annotations: map[string]string{
				AWSAnnotationRole:            roleARN,
				AWSAnnotationAudience:        audience,
				AWSAnnotationTokenExpiration: "3600",
			},
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
			// Mint a recognizable token so the STS request body can be tied
			// back to the TokenRequest, and record what VSO asked for.
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
				Role:               "vso-vault-role",
				Region:             "us-east-1",
				SessionName:        sessionName,
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

	require.Len(t, tokenRequests, 1, "expected exactly one ServiceAccount TokenRequest")
	assert.Equal(t, []string{audience}, tokenRequests[0].Audiences)
	require.NotNil(t, tokenRequests[0].ExpirationSeconds)
	assert.Equal(t, int64(3600), *tokenRequests[0].ExpirationSeconds)

	require.Len(t, stsCalls, 1, "expected exactly one STS call")
	call := stsCalls[0]
	assert.Equal(t, "AssumeRoleWithWebIdentity", call.Get("Action"))
	assert.Equal(t, saToken, call.Get("WebIdentityToken"),
		"the requested ServiceAccount token must be the one presented to STS")
	assert.Equal(t, roleARN, call.Get("RoleArn"))
	assert.Equal(t, sessionName, call.Get("RoleSessionName"))

	// The Vault login payload must be signed with the credentials returned by
	// AssumeRoleWithWebIdentity, which proves the assumed role - not some other
	// provider in the chain - produced them.
	assert.Equal(t, "vso-vault-role", loginData["role"])

	rawURL, err := base64.StdEncoding.DecodeString(loginData["iam_request_url"].(string))
	require.NoError(t, err)
	loginURL, err := url.Parse(string(rawURL))
	require.NoError(t, err)
	stsURL, err := url.Parse(stsServer.URL)
	require.NoError(t, err)
	assert.Equal(t, stsURL.Host, loginURL.Host, "login request must target the configured STS endpoint")

	rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
	require.NoError(t, err)
	var headers map[string][]string
	require.NoError(t, json.Unmarshal(rawHeaders, &headers))
	require.NotEmpty(t, headers["Authorization"])
	assert.Contains(t, headers["Authorization"][0], "AKIAIRSAONLY",
		"login request must be signed with the web identity credentials")
	assert.Equal(t, []string{"irsa-session-token"}, headers["X-Amz-Security-Token"])
}

// Test_GetCreds_IRSAOnly_DefaultAudienceAndExpiration covers the same
// IRSA-only flow when the ServiceAccount carries just the role-arn annotation,
// confirming the documented audience/expiration defaults are applied and that
// the credential chain still resolves via web identity rather than node
// credentials.
func Test_GetCreds_IRSAOnly_DefaultAudienceAndExpiration(t *testing.T) {
	isolateAWSEnvironment(t)

	const (
		roleARN   = "arn:aws:iam::123456789012:role/vso-irsa-role"
		saName    = "vso-irsa-sa"
		namespace = "vso-test-ns"
	)

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
			Name:        saName,
			Namespace:   namespace,
			UID:         "sa-uid",
			Annotations: map[string]string{AWSAnnotationRole: roleARN},
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
				tr.Status.Token = "default-audience-token"
				return nil
			},
		}).
		Build()

	authObj := &secretsv1beta1.VaultAuth{
		ObjectMeta: metav1.ObjectMeta{Name: "vault-auth", Namespace: namespace},
		Spec: secretsv1beta1.VaultAuthSpec{
			Method: "aws",
			AWS: &secretsv1beta1.VaultAuthConfigAWS{
				Role:               "vso-vault-role",
				Region:             "us-east-1",
				STSEndpoint:        stsServer.URL,
				IRSAServiceAccount: saName,
			},
		},
	}

	ctx := context.Background()
	provider := &AWSCredentialProvider{}
	require.NoError(t, provider.Init(ctx, client, authObj, namespace))

	_, err := provider.GetCreds(ctx, client)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()

	require.Empty(t, imdsHits, "VSO must not fall back to EC2 instance metadata / node credentials")

	require.Len(t, tokenRequests, 1)
	assert.Equal(t, []string{AWSDefaultAudience}, tokenRequests[0].Audiences)
	require.NotNil(t, tokenRequests[0].ExpirationSeconds)
	assert.Equal(t, AWSDefaultTokenExpiration, *tokenRequests[0].ExpirationSeconds)

	require.Len(t, stsCalls, 1)
	assert.Equal(t, "AssumeRoleWithWebIdentity", stsCalls[0].Get("Action"))
	assert.Equal(t, "default-audience-token", stsCalls[0].Get("WebIdentityToken"))
	assert.Equal(t, roleARN, stsCalls[0].Get("RoleArn"))
}

// ─── from aws_node_role_test.go ───

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

// Test_GetCreds_NodeCredentialsWithRoleARN verifies that when AWS_ROLE_ARN is
// set in the operator's environment and EC2 instance metadata credentials are
// available, with no static credentials, no shared profile, and no web identity
// configuration (no secretRef, no irsaServiceAccount, no
// AWS_WEB_IDENTITY_TOKEN_FILE), VSO uses the node credentials to assume the
// configured role and then authenticates to Vault with the assumed-role
// credentials.
//
// This is the behavior of the pre-v2 implementation (awsutil v0 / AWS SDK v1),
// which built an stscreds.AssumeRoleProvider explicitly. aws-sdk-go-v2 only
// chains an AssumeRoleProvider when *sharedConfig*.RoleARN is set (role_arn in
// ~/.aws/config); envConfig.RoleARN (AWS_ROLE_ARN) is consulted solely on the
// web identity path, and awsutil's config.WithAssumeRoleCredentialOptions is
// silently discarded. applyCredentialsOverride restores it.
func Test_GetCreds_NodeCredentialsWithRoleARN(t *testing.T) {
	isolateAWSEnvironment(t)

	const (
		assumeRoleARN = "arn:aws:iam::123456789012:role/vso-target-role"
		sessionName   = "vso-node-session"
	)

	imds := &fakeIMDS{}
	imdsServer := imds.start(t)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)

	// AWS_ROLE_ARN is picked up by awsutil.NewCredentialsConfig, which reads it
	// straight from the environment into CredentialsConfig.RoleARN. VSO itself
	// has no spec field for it.
	t.Setenv("AWS_ROLE_ARN", assumeRoleARN)
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

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, secretsv1beta1.AddToScheme(scheme))

	// With neither secretRef nor irsaServiceAccount set, Init derives its UID
	// from the kube-root-ca.crt ConfigMap in the operator namespace.
	rootCA := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      K8sRootCA,
			Namespace: common.OperatorNamespace,
			UID:       "root-ca-uid",
		},
	}
	client := fake.NewClientBuilder().WithScheme(scheme).WithObjects(rootCA).Build()

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

	// The node credentials were sourced from IMDS and used to sign AssumeRole.
	assert.Contains(t, imds.paths(), "/latest/meta-data/iam/security-credentials/",
		"expected the EC2 role provider to supply the assume-role source credentials")

	mu.Lock()
	calls := append([]url.Values(nil), stsCalls...)
	mu.Unlock()

	require.Len(t, calls, 1, "expected exactly one STS call")
	assert.Equal(t, "AssumeRole", calls[0].Get("Action"),
		"the configured role must be assumed rather than used directly")
	assert.Equal(t, assumeRoleARN, calls[0].Get("RoleArn"))
	assert.Equal(t, sessionName, calls[0].Get("RoleSessionName"))

	rawHeaders, err := base64.StdEncoding.DecodeString(loginData["iam_request_headers"].(string))
	require.NoError(t, err)
	var headers map[string][]string
	require.NoError(t, json.Unmarshal(rawHeaders, &headers))
	require.NotEmpty(t, headers["Authorization"])
	authHeader := headers["Authorization"][0]

	assert.Contains(t, authHeader, "AKIAASSUMEDROLE",
		"Vault login must be signed with the assumed-role credentials")
	assert.NotContains(t, authHeader, nodeAccessKeyID,
		"Vault login must not be signed with the raw node credentials")
	assert.Equal(t, []string{"assumed-session-token"}, headers["X-Amz-Security-Token"])
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

// Test_applyCredentialsOverride_NoOpWithoutRoleARN confirms the override leaves
// the credential chain untouched when no role is configured at all, so plain
// node/instance-profile authentication still works.
func Test_applyCredentialsOverride_NoOpWithoutRoleARN(t *testing.T) {
	isolateAWSEnvironment(t)

	imds := &fakeIMDS{}
	imdsServer := imds.start(t)
	t.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.URL)
	t.Setenv("AWS_REGION", "us-east-1")

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
	assert.Equal(t, nodeAccessKeyID, creds.AccessKeyID,
		"the chain resolves to node credentials")
	assert.True(t, strings.Contains(creds.Source, "IMDS") || strings.Contains(creds.Source, "EC2"),
		"expected IMDS-sourced credentials, got source %q", creds.Source)
}

// ─── from aws_precedence_test.go ───

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

// ─── from aws_sts_endpoint_repro_test.go ───

// hitRecordingTransport records the full URL of every outbound request and
// fails it immediately without touching the network, so the test proves
// *where* the SDK tried to send the request regardless of whether the
// request could ever succeed.
type hitRecordingTransport struct {
	hits []string
}

func (t *hitRecordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.hits = append(t.hits, req.URL.String())
	return nil, http.ErrHandlerTimeout
}

// forwardingTransport records the full URL of every outbound request and
// then actually performs it, so a request to a local httptest.Server behaves
// normally while (in this offline test) any request to a real external host
// simply fails due to the sandboxed environment's lack of network access.
type forwardingTransport struct {
	hits []string
}

func (t *forwardingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.hits = append(t.hits, req.URL.String())
	return http.DefaultTransport.RoundTrip(req)
}

type stsEndpointResolverFunc func(context.Context, sts.EndpointParameters) (smithyendpoints.Endpoint, error)

func (f stsEndpointResolverFunc) ResolveEndpoint(ctx context.Context, params sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
	return f(ctx, params)
}

// Test_GenerateCredentialChain_IgnoresCustomSTSEndpoint_IRSA reproduces the
// review finding that awsutil.CredentialsConfig.STSEndpointResolver, as wired
// up by AWSCredentialProvider.getCredentialsConfig (see aws.go) whenever
// authObj.Spec.AWS.STSEndpoint != "", is never propagated into the
// WebIdentityRoleProvider that GenerateCredentialChain builds internally for
// the IRSA flow (RoleARN + WebIdentityToken).
//
// aws-sdk-go-v2/config's resolveCredentialChain (resolve_credentials.go)
// constructs that provider as:
//
//	stscreds.NewWebIdentityRoleProvider(sts.NewFromConfig(*cfg), roleARN, ...)
//
// with no sts.WithEndpointResolverV2(...) override. VSO's STSEndpointResolver
// is only ever applied in awsutil's separate STSClient()/IAMClient() helper
// functions (clients.go), which GenerateCredentialChain does not call. So the
// credential-fetching AssumeRoleWithWebIdentity call always goes to the
// default regional AWS STS endpoint, while only the final, separately-built
// GetCallerIdentity login request (VSO's own generateLoginData) honors
// stsEndpoint.
func Test_GenerateCredentialChain_IgnoresCustomSTSEndpoint_IRSA(t *testing.T) {
	dir := t.TempDir()

	// Point shared config/credentials at nonexistent paths and clear
	// AWS_PROFILE so pre-existing ~/.aws state on the test machine can't
	// influence which credential provider the SDK selects.
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "nonexistent-credentials"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "nonexistent-config"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")

	// aws-sdk-go-v2/config only engages the WebIdentityRoleProvider when
	// AWS_WEB_IDENTITY_TOKEN_FILE (or an equivalent shared-config value) is
	// present, so set it here to exercise the same code path a real
	// EKS/IRSA pod would hit (VSO obtains the token content itself via the
	// Kubernetes TokenRequest API rather than a mounted file, but that only
	// affects how the token is supplied, not which STS endpoint gets used).
	tokenFile := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte("fake-jwt-token"), 0o600))
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", tokenFile)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/test-irsa-role")

	customSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer customSTS.Close()

	customURL, err := url.Parse(customSTS.URL)
	require.NoError(t, err)

	transport := &hitRecordingTransport{}

	// This mirrors AWSCredentialProvider.getCredentialsConfig exactly: a
	// fresh CredentialsConfig with RoleARN + WebIdentityToken set from the
	// fetched IRSA service account token, and STSEndpointResolver set from
	// authObj.Spec.AWS.STSEndpoint.
	cfg, err := awsutil.NewCredentialsConfig()
	require.NoError(t, err)
	cfg.Region = "us-east-1"
	cfg.RoleARN = "arn:aws:iam::123456789012:role/test-irsa-role"
	cfg.WebIdentityTokenFile = tokenFile
	cfg.HTTPClient = &http.Client{Transport: transport}
	cfg.STSEndpointResolver = stsEndpointResolverFunc(func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
		return smithyendpoints.Endpoint{URI: *customURL}, nil
	})

	awsCfg, err := cfg.GenerateCredentialChain(context.Background())
	require.NoError(t, err)

	// Force credential retrieval, which triggers the internal
	// AssumeRoleWithWebIdentity STS call.
	_, retrieveErr := awsCfg.Credentials.Retrieve(context.Background())
	t.Logf("retrieve error (expected; transport rejects all requests): %v", retrieveErr)

	require.NotEmpty(t, transport.hits, "expected the WebIdentityRoleProvider to make an STS call")

	var sawDefaultSTSEndpoint bool
	for _, hit := range transport.hits {
		require.NotContains(t, hit, customURL.Host,
			"BUG NOT REPRODUCED: credential provider used the custom STS endpoint; expected it to bypass STSEndpointResolver and hit the default AWS STS endpoint")
		if strings.Contains(hit, "sts.us-east-1.amazonaws.com") {
			sawDefaultSTSEndpoint = true
		}
	}
	require.True(t, sawDefaultSTSEndpoint, "expected a call to the default regional STS endpoint; hits: %v", transport.hits)

	t.Logf("confirmed: GenerateCredentialChain's WebIdentityRoleProvider ignored STSEndpointResolver (%q) and called %v instead",
		customSTS.URL, transport.hits)
}

// Test_applyCredentialsOverride_FixesCustomSTSEndpoint verifies the
// fix in aws.go: applyCredentialsOverride rebuilds the IRSA
// credentials provider itself, using an STS client that honors a custom
// STSEndpointResolver, instead of relying on GenerateCredentialChain's
// built-in (and, per the test above, broken) wiring.
//
// It also uses a raw in-memory WebIdentityToken (no AWS_WEB_IDENTITY_TOKEN_FILE
// env var, no token file) to mirror VSO's actual runtime behavior, where the
// IRSA token is fetched via the Kubernetes TokenRequest API and never written
// to disk or exported as an environment variable.
func Test_applyCredentialsOverride_FixesCustomSTSEndpoint(t *testing.T) {
	dir := t.TempDir()

	// Isolate shared config/credentials and deliberately leave
	// AWS_WEB_IDENTITY_TOKEN_FILE/AWS_ROLE_ARN unset, matching VSO's actual
	// environment: the token is supplied only via CredentialsConfig, not the
	// process environment.
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "nonexistent-credentials"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "nonexistent-config"))
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_REGION", "us-east-1")

	customSTS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIAFAKE</AccessKeyId>
      <SecretAccessKey>fakesecret</SecretAccessKey>
      <SessionToken>faketoken</SessionToken>
      <Expiration>2999-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`))
	}))
	defer customSTS.Close()

	customURL, err := url.Parse(customSTS.URL)
	require.NoError(t, err)

	transport := &forwardingTransport{}

	cfg, err := awsutil.NewCredentialsConfig()
	require.NoError(t, err)
	cfg.Region = "us-east-1"
	cfg.RoleARN = "arn:aws:iam::123456789012:role/test-irsa-role"
	cfg.WebIdentityToken = "fake-jwt-token" // raw content, exactly like VSO's irsaToken
	cfg.HTTPClient = &http.Client{Transport: transport}
	cfg.STSEndpointResolver = stsEndpointResolverFunc(func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
		return smithyendpoints.Endpoint{URI: *customURL}, nil
	})

	awsCfg, err := cfg.GenerateCredentialChain(context.Background())
	require.NoError(t, err)

	applyCredentialsOverride(awsCfg, cfg, nil, "")

	creds, retrieveErr := awsCfg.Credentials.Retrieve(context.Background())
	require.NoError(t, retrieveErr, "expected the fixed provider to successfully retrieve credentials")
	require.Equal(t, "AKIAFAKE", creds.AccessKeyID)

	require.NotEmpty(t, transport.hits, "expected an STS call")
	for _, hit := range transport.hits {
		require.Contains(t, hit, customURL.Host,
			"expected the credential provider to use the configured custom STS endpoint")
	}
	t.Logf("confirmed fix: credentials were retrieved via the custom STS endpoint %q (hits: %v)", customSTS.URL, transport.hits)
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

// Test_applyCredentialsOverride_ExplicitIRSAPrefersInlineToken pins down which
// web identity token the IRSA flow presents to STS.
//
// When VSO runs on EKS the operator pod has its own AWS_WEB_IDENTITY_TOKEN_FILE
// mounted for its own identity. A VaultAuth naming an irsaServiceAccount must
// present the ServiceAccount token VSO requested for it, not the operator's
// ambient token file, otherwise the login is performed under the wrong identity.
func Test_applyCredentialsOverride_ExplicitIRSAPrefersInlineToken(t *testing.T) {
	isolateAWSEnvironment(t)

	// The operator pod's own token file, which must be ignored here.
	operatorTokenFile := filepath.Join(t.TempDir(), "operator-token")
	require.NoError(t, os.WriteFile(operatorTokenFile, []byte("operator-pod-jwt"), 0o600))
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", operatorTokenFile)
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/operator-role")

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

	const (
		vaultAuthRoleARN = "arn:aws:iam::123456789012:role/vaultauth-irsa-role"
		vaultAuthToken   = "vaultauth-service-account-jwt"
	)

	p := &AWSCredentialProvider{
		authObj: &secretsv1beta1.VaultAuth{
			Spec: secretsv1beta1.VaultAuthSpec{
				AWS: &secretsv1beta1.VaultAuthConfigAWS{
					Role: "r", Region: "us-east-1", SessionName: "vso-session",
				},
			},
		},
	}
	irsa := &IRSAConfig{RoleARN: vaultAuthRoleARN}
	cfg, err := p.getCredentialsConfig(&corev1.Secret{}, irsa, vaultAuthToken)
	require.NoError(t, err)
	cfg.STSEndpointResolver = stsEndpointResolverFunc(
		func(_ context.Context, _ sts.EndpointParameters) (smithyendpoints.Endpoint, error) {
			return smithyendpoints.Endpoint{URI: *stsURL}, nil
		})

	awsCfg, err := cfg.GenerateCredentialChain(context.Background())
	require.NoError(t, err)

	applyCredentialsOverride(awsCfg, cfg, irsa, vaultAuthToken)

	_, err = awsCfg.Credentials.Retrieve(context.Background())
	require.NoError(t, err)

	mu.Lock()
	calls := append([]url.Values(nil), stsCalls...)
	mu.Unlock()

	require.Len(t, calls, 1)
	assert.Equal(t, "AssumeRoleWithWebIdentity", calls[0].Get("Action"))
	assert.Equal(t, vaultAuthToken, calls[0].Get("WebIdentityToken"),
		"must present the VaultAuth ServiceAccount token, not the operator pod's token file")
	assert.Equal(t, vaultAuthRoleARN, calls[0].Get("RoleArn"),
		"must assume the VaultAuth's role, not the operator's inherited role")
	assert.Equal(t, "vso-session", calls[0].Get("RoleSessionName"),
		"sessionName from the VaultAuth spec must be propagated")
}
