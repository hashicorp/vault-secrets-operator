# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  # k8s locals
  k8s_namespace = "vault-secrets-operator-system"

  # auth locals
  auth_role_operator = "auth-role-operator"

  # transit locals
  operator_service_account_name = "vault-secrets-operator-transit"
  operator_namespace            = var.deploy_operator_via_helm ? one(module.vso-helm[*].operator_namespace) : one(data.kubernetes_namespace.operator[*].metadata[0].name)
}
