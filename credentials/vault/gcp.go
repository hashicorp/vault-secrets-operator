// Copyright IBM Corp. 2022, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"

	"cloud.google.com/go/compute/metadata"
	"google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
	stsv1 "google.golang.org/api/sts/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/helpers"
)

var _ CredentialProvider = (*GCPCredentialProvider)(nil)

const GCPAnnotationServiceAccount = "iam.gke.io/gcp-service-account"

type GCPCredentialProvider struct {
	authObj           *secretsv1beta1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *GCPCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *GCPCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *GCPCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1beta1.VaultAuth, providerNamespace string) error {
	if authObj.Spec.GCP == nil {
		return fmt.Errorf("GCP auth method not configured")
	}
	if err := authObj.Spec.GCP.Validate(); err != nil {
		return fmt.Errorf("invalid GCP auth configuration: %w", err)
	}

	l.authObj = authObj
	l.providerNamespace = providerNamespace

	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.GCP.WorkloadIdentityServiceAccount,
	}
	workloadIdentitySA, err := helpers.GetServiceAccount(ctx, client, key)
	if err != nil {
		return err
	}
	l.uid = workloadIdentitySA.UID

	return nil
}

func (l *GCPCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)

	var err error
	gcpProject := l.authObj.Spec.GCP.ProjectID
	if gcpProject == "" {
		gcpProject, err = metadata.ProjectID()
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GCP project from compute metadata: %w", err)
		}
	}
	gkeLocation := l.authObj.Spec.GCP.Region
	if gkeLocation == "" {
		gkeLocation, err = metadata.InstanceAttributeValue("cluster-location")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GKE cluster location from instance metadata: %w", err)
		}
	}
	gkeName := l.authObj.Spec.GCP.ClusterName
	if gkeName == "" {
		gkeName, err = metadata.InstanceAttributeValue("cluster-name")
		if err != nil {
			return nil, fmt.Errorf("failed to fetch GKE cluster name from instance metadata: %w", err)
		}
	}

	// Retrieve the workload identity k8s service account
	key := ctrlclient.ObjectKey{
		Namespace: l.providerNamespace,
		Name:      l.authObj.Spec.GCP.WorkloadIdentityServiceAccount,
	}
	sa, err := helpers.GetServiceAccount(ctx, client, key)
	if err != nil {
		logger.Error(err, "Failed to get service account")
		return nil, err
	}

	// Create and exchange a k8s token for a Google ID token (signed jwt)
	config := GCPTokenExchangeConfig{
		KSA:            sa,
		GKEClusterName: gkeName,
		GCPProject:     gcpProject,
		Region:         gkeLocation,
		VaultRole:      l.authObj.Spec.GCP.Role,
	}
	signedJwt, err := GCPTokenExchange(ctx, config, client)
	if err != nil {
		return nil, fmt.Errorf("failed GCP token exchange: %w", err)
	}

	// Pass back the signed jwt as loginData
	loginData := map[string]any{
		"role": l.authObj.Spec.GCP.Role,
		"jwt":  signedJwt,
	}
	return loginData, nil
}

type GCPTokenExchangeConfig struct {
	KSA            *corev1.ServiceAccount
	GKEClusterName string
	GCPProject     string
	Region         string
	VaultRole      string
}

// GCPTokenExchange creates and exchanges a k8s service account token for a
// federated access token from Google's STS API, and uses the federated access
// token to get an ID token (signed jwt) from Google's IAM API, which can then
// be used to auth to Vault
func GCPTokenExchange(ctx context.Context, config GCPTokenExchangeConfig, client ctrlclient.Client) (string, error) {
	// Read the GCP service account (GSA) from the k8s service account (KSA)
	// annotation
	gsa := ""
	if v, ok := config.KSA.Annotations[GCPAnnotationServiceAccount]; ok {
		gsa = v
	} else {
		return "", fmt.Errorf("workload identity service account %q is missing annotation %q", config.KSA.Name, GCPAnnotationServiceAccount)
	}

	workloadIdentityPool := fmt.Sprintf("%s.svc.id.goog", config.GCPProject)
	k8sTokenRequest, err := helpers.RequestSAToken(ctx, client, config.KSA, 600, []string{workloadIdentityPool})
	if err != nil {
		return "", fmt.Errorf("failed to get service account token: %w", err)
	}

	identityProvider := fmt.Sprintf(
		"https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s",
		config.GCPProject, config.Region, config.GKEClusterName,
	)
	fedTokenAudience := fmt.Sprintf("identitynamespace:%s:%s", workloadIdentityPool, identityProvider)

	// Use that k8s token with Google's STS API to get a Google federated access
	// token. Use WithoutAuthentication() to prevent picking up the instance
	// credentials.
	stsService, err := stsv1.NewService(ctx, option.WithoutAuthentication())
	if err != nil {
		return "", fmt.Errorf("failed to dial Google STS: %w", err)
	}
	stsTokenResp, err := stsService.V1.Token(&stsv1.GoogleIdentityStsV1ExchangeTokenRequest{
		SubjectToken:       k8sTokenRequest.Status.Token,
		SubjectTokenType:   "urn:ietf:params:oauth:token-type:jwt",
		RequestedTokenType: "urn:ietf:params:oauth:token-type:access_token",
		GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
		Scope:              "https://www.googleapis.com/auth/iam",
		Audience:           fedTokenAudience,
	}).Do()
	if err != nil {
		return "", fmt.Errorf("failed to exchange k8s service account token for google federated token: %w", err)
	}
	if stsTokenResp == nil || stsTokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty token response when exchanging k8s service account token for google federated token")
	}

	// Use that access token to generate an ID token (signed jwt). Use
	// WithoutAuthentication() to prevent picking up the instance credentials.
	iamService, err := iamcredentials.NewService(ctx, option.WithoutAuthentication())
	if err != nil {
		return "", fmt.Errorf("failed to dial Google IAM: %w", err)
	}
	idTokenCall := iamService.Projects.ServiceAccounts.GenerateIdToken(
		"projects/-/serviceAccounts/"+gsa,
		&iamcredentials.GenerateIdTokenRequest{
			Audience:     fmt.Sprintf("https://vault/%s", config.VaultRole),
			IncludeEmail: true,
		},
	)
	idTokenCall.Header().Set("Authorization", "Bearer "+stsTokenResp.AccessToken)
	idTokenCall.Context(ctx)
	idTokenResp, err := idTokenCall.Do()
	if err != nil {
		return "", fmt.Errorf("failed to exchange Google federated token for id token: %w", err)
	}
	return idTokenResp.Token, nil
}
