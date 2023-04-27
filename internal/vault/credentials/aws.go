// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentials

import (
	"context"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/uuid"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/hashicorp/go-secure-stdlib/awsutil"
	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"github.com/hashicorp/vault-secrets-operator/internal/consts"
)

const (
	AWSAnnotationRole            = "eks.amazonaws.com/role-arn"
	AWSAnnotationAudience        = "eks.amazonaws.com/audience"
	AWSAnnotationTokenExpiration = "eks.amazonaws.com/token-expiration"
	AWSDefaultAudience           = "sts.amazonaws.com"
	AWSDefaultTokenExpiration    = int64(86400)
)

var _ CredentialProvider = (*AWSCredentialProvider)(nil)

type AWSCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *AWSCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *AWSCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *AWSCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace

	if l.authObj.Spec.AWS.AWSCredsRef != "" {
		// If AWSCredsRef is not empty, get the secret and read the creds from
		// there, use the secret UID as l.uid
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.AWSCredsRef,
		}
		credsSecret, err := getSecret(ctx, client, key)
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
		irsaServiceAccount, err := getSA(ctx, client, key)
		if err != nil {
			return err
		}
		l.uid = irsaServiceAccount.UID
	} else {
		// At this point either the node role or the instance profile will be
		// used for credentials, so just generate a new UID
		l.uid = uuid.NewUUID()
	}

	return nil
}

func (l *AWSCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	logger := log.FromContext(ctx)
	credsSecret := &corev1.Secret{}
	irsaToken := ""
	var irsaConfig *IRSAConfig

	if l.authObj.Spec.AWS.AWSCredsRef != "" {
		var err error
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.AWSCredsRef,
		}
		credsSecret, err = getSecret(ctx, client, key)
		if err != nil {
			logger.Error(err, "Failed to get secret", "secret_name", l.authObj.Spec.AWS.AWSCredsRef)
			return nil, err
		}
	}
	if l.authObj.Spec.AWS.IRSAServiceAccount != "" {
		key := ctrlclient.ObjectKey{
			Namespace: l.providerNamespace,
			Name:      l.authObj.Spec.AWS.IRSAServiceAccount,
		}
		irsaServiceAccount, err := getSA(ctx, client, key)
		if err != nil {
			logger.Error(err, "Failed to get IRSA service account", "service_account", l.authObj.Spec.AWS.IRSAServiceAccount)
			return nil, err
		}
		irsaConfig = getIRSAConfig(irsaServiceAccount.Annotations)

		token, err := requestSAToken(ctx, client, irsaServiceAccount, irsaConfig.TokenExpiration, []string{irsaConfig.Audience})
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
	// config.Logger = ...

	creds, err := config.GenerateCredentialChain()
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

type IRSAConfig struct {
	// eks.amazonaws.com/role-arn
	RoleARN string
	// eks.amazonaws.com/audience
	Audience string
	// eks.amazonaws.com/token-expiration
	TokenExpiration int64
}

func getIRSAConfig(annotations map[string]string) *IRSAConfig {
	// Set defaults
	config := &IRSAConfig{
		Audience:        AWSDefaultAudience,
		TokenExpiration: AWSDefaultTokenExpiration,
	}

	// Set the role arn
	if v, ok := annotations[AWSAnnotationRole]; ok {
		config.RoleARN = v
	}

	// Override defaults from any annotations set
	if v, ok := annotations[AWSAnnotationAudience]; ok {
		config.Audience = v
	}
	if v, ok := annotations[AWSAnnotationTokenExpiration]; ok {
		check, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			check = 86400
		}
		config.TokenExpiration = check
	}

	return config
}
