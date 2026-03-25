# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

locals {
  # common locals
  name_prefix      = "demo"
  namespace        = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
  tenant_namespace = var.vault_enterprise ? vault_namespace.tenant[0].path_fq : null

  # k8s locals
  k8s_namespace_name = "${local.name_prefix}-ns"
  # used to avoid duplicate declarations in in referring resources
  k8s_namespace = kubernetes_namespace.dev.metadata[0].name

  # auth locals
  auth_mount         = "${local.name_prefix}-auth-mount"
  auth_policy        = "${local.name_prefix}-auth-policy"
  auth_role          = "auth-role"
  auth_role_operator = "auth-role-operator"

  # db locals
  postgres_host = "${data.kubernetes_service.postgres.metadata[0].name}.${helm_release.postgres.namespace}.svc.cluster.local:${data.kubernetes_service.postgres.spec[0].port[0].port}"
  db_creds_path = "creds/${var.db_role}"

  operator_service_account_name    = "vault-secrets-operator-transit"
  csi_enabled                      = var.vault_enterprise ? true : var.csi_enabled
  bound_service_account_namespaces = concat([local.k8s_namespace], local.csi_enabled ? [kubernetes_namespace.demo-ns-vso-csi[0].metadata[0].name] : [])
  default_token_policies           = concat([vault_policy.db.name], local.csi_enabled ? [vault_policy.csi-secrets[0].name] : [])
  k8s_vault_connection_address     = var.k8s_vault_connection_address != "" ? var.k8s_vault_connection_address : "http://vault.vault.svc.cluster.local:8200"
}
