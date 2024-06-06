// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/awsutil"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	secretsv1beta1 "github.com/hashicorp/vault-secrets-operator/api/v1beta1"
	"github.com/hashicorp/vault-secrets-operator/internal/common"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
	"github.com/hashicorp/vault-secrets-operator/internal/helpers"
)

const (
	AWSAnnotationRole            = "eks.amazonaws.com/role-arn"
	AWSAnnotationAudience        = "eks.amazonaws.com/audience"
	AWSAnnotationTokenExpiration = "eks.amazonaws.com/token-expiration"
	AWSDefaultAudience           = "sts.amazonaws.com"
	AWSDefaultTokenExpiration    = int64(86400)
	K8sRootCA                    = "kube-root-ca.crt"
)

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

	// TODO: convert logr to something compatible with hclog for use in the
	// awsutil functions
	config.Logger = hclog.Default()
	config.Logger.SetLevel(hclog.Debug)

	creds, err := config.GenerateCredentialChain(awsutil.WithSkipWebIdentityValidity(true))
	if err != nil {
		return nil, err
	}

	headerValue := l.authObj.Spec.AWS.HeaderValue

	loginData, err := awsutil.GenerateLoginData(creds, headerValue, config.Region, config.Logger)
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
		config.STSEndpoint = l.authObj.Spec.AWS.STSEndpoint
	}
	if l.authObj.Spec.AWS.IAMEndpoint != "" {
		config.IAMEndpoint = l.authObj.Spec.AWS.IAMEndpoint
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
