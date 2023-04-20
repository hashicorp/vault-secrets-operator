// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentialproviders

import (
	"context"
	"strings"

	secretsv1alpha1 "github.com/hashicorp/vault-secrets-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type ApproleCredentialProvider struct {
	authObj           *secretsv1alpha1.VaultAuth
	providerNamespace string
	uid               types.UID
}

func (l *ApproleCredentialProvider) GetNamespace() string {
	return l.providerNamespace
}

func (l *ApproleCredentialProvider) GetUID() types.UID {
	return l.uid
}

func (l *ApproleCredentialProvider) Init(ctx context.Context, client ctrlclient.Client, authObj *secretsv1alpha1.VaultAuth, providerNamespace string) error {
	l.authObj = authObj
	l.providerNamespace = providerNamespace
	return nil
}

func (l *ApproleCredentialProvider) GetCreds(ctx context.Context, client ctrlclient.Client) (map[string]interface{}, error) {
	// logger := log.FromContext(ctx)

	// fetch the secretID

	// credentials needed for approle auth
	creds := map[string]interface{}{
		"role_id":   l.authObj.Spec.AppRole.Role,
		"secret_id": l.authObj.Spec.AppRole.Role,
	}
	if len(l.authObj.Spec.AppRole.CidrList) != 0 {
		creds["cidr_list"] = strings.Join(l.authObj.Spec.AppRole.CidrList, ",")
	}

	return creds, nil
}
