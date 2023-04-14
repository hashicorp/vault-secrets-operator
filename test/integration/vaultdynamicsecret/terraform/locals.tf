# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

locals {
  # common locals
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"
  namespace   = var.vault_enterprise ? vault_namespace.test[0].path_fq : null

  # k8s locals
  k8s_namespace = "${local.name_prefix}-k8s-ns"

  # auth locals
  auth_mount            = "${local.name_prefix}-auth-mount"
  kubernetes_auth_mount = "${local.auth_mount}-kubernetes"
  jwt_auth_mount        = "${local.auth_mount}-jwt"

  auth_policy        = "${local.name_prefix}-auth-policy"
  auth_role          = "auth-role"
  auth_role_operator = "auth-role-operator"

  # db locals
  postgres_host = "${data.kubernetes_service.postgres.metadata[0].name}.${helm_release.postgres.namespace}.svc.cluster.local:${data.kubernetes_service.postgres.spec[0].port[0].port}"
  db_role       = "dev-postgres"
}
