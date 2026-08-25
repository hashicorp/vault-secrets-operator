// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsutil "github.com/hashicorp/go-secure-stdlib/awsutil/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
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
		SessionToken:    "",
		Source:          "test",
	}

	endpoint := stsSigningEndpoint{
		requestURL:    "https://sts.us-east-1.amazonaws.com",
		signingName:   stsSigningName,
		signingRegion: "us-east-1",
	}

	t.Run("produces correct method and body", func(t *testing.T) {
		req, body, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "us-east-1", "")
		require.NoError(t, err)
		assert.Equal(t, http.MethodPost, req.Method)
		assert.Equal(t, stsGetCallerIdentityBody, body)
		assert.Equal(t, stsContentType, req.Header.Get("Content-Type"))
	})

	t.Run("sets X-Vault-AWS-IAM-Server-ID header when provided", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "us-east-1", "vault.example.com")
		require.NoError(t, err)
		assert.Equal(t, "vault.example.com", req.Header.Get(iamServerIDHeader))
	})

	t.Run("does not set X-Vault-AWS-IAM-Server-ID when empty", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "us-east-1", "")
		require.NoError(t, err)
		assert.Empty(t, req.Header.Get(iamServerIDHeader))
	})

	t.Run("request is signed (Authorization header present)", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "us-east-1", "")
		require.NoError(t, err)
		assert.NotEmpty(t, req.Header.Get("Authorization"), "signed request must have Authorization header")
		assert.Contains(t, req.Header.Get("Authorization"), "AWS4-HMAC-SHA256")
	})

	t.Run("request URL matches endpoint", func(t *testing.T) {
		req, _, err := buildSignedGetCallerIdentityRequest(ctx, creds, endpoint, "us-east-1", "")
		require.NoError(t, err)
		assert.Equal(t, "https://sts.us-east-1.amazonaws.com", req.URL.String())
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
