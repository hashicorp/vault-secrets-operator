# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  # common locals
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"
  namespace   = var.vault_enterprise ? vault_namespace.test[0].path_fq : null

  # k8s locals
  k8s_namespace = "${local.name_prefix}-k8s-ns"

  # auth locals
  auth_mount         = "${local.name_prefix}-auth-mount"
  auth_policy        = "${local.name_prefix}-auth-policy"
  auth_role          = "auth-role"
  auth_role_operator = "auth-role-operator"

  # db locals
  postgres_host       = "${data.kubernetes_service.postgres.metadata[0].name}.${helm_release.postgres.namespace}.svc.cluster.local:${data.kubernetes_service.postgres.spec[0].port[0].port}"
  db_role             = "dev-postgres"
  db_role_static      = "${local.db_role}-static"
  db_role_static_user = "${local.db_role_static}-user"

  # transit locals
  operator_service_account_name = "${local.name_prefix}-operator"
  operator_namespace            = var.deploy_operator_via_helm ? one(module.vso-helm[*].operator_namespace) : one(data.kubernetes_namespace.operator[*].metadata[0].name)
}
