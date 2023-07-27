// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault-secrets-operator/internal/common"
	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	operatorDeploymentDefaultName = "vault-secrets-operator-controller-manager"
	operatorDeploymentKind        = "Deployment"
	operatorDeploymentAPIVersion  = "apps/v1"
)

// JoinPath for Vault requests.
func JoinPath(parts ...string) string {
	return strings.Join(parts, "/")
}

func getOperatorDeployment(c client.Client) (*appsv1.Deployment, error) {
	operatorDeploymentName := ""
	if operatorDeploymentName = os.Getenv("OPERATOR_DEPLOYMENT_NAME"); operatorDeploymentName == "" {
		operatorDeploymentName = operatorDeploymentDefaultName
	}
	deployment := appsv1.Deployment{}
	err := c.Get(context.Background(), types.NamespacedName{
		Namespace: common.OperatorNamespace,
		Name:      operatorDeploymentName,
	}, &deployment)
	return &deployment, err
}

func GetOperatorDeploymentOwnerReference(c client.Client) (*metav1.OwnerReference, error) {
	deployment, err := getOperatorDeployment(c)
	if err != nil {
		return nil, err
	}
	fmt.Print("Deployment", deployment, "\n")
	return &metav1.OwnerReference{
		APIVersion: operatorDeploymentAPIVersion,
		Kind:       operatorDeploymentKind,
		Name:       deployment.Name,
		UID:        deployment.UID,
	}, nil
}
