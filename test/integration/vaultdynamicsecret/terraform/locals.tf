# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

locals {
  # common locals
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"
  namespace   = var.vault_enterprise ? vault_namespace.test[0].path_fq : null

  # k8s locals
  k8s_namespace = "${local.name_prefix}-k8s-ns"

  # auth locals
  auth_mount         = "${local.name_prefix}-auth-mount"
  auth_mount_xns     = "${local.name_prefix}-auth-mount-xns"
  auth_policy        = "${local.name_prefix}-auth-policy"
  auth_role          = "auth-role"
  auth_role_xns      = "auth-role-xns"
  auth_role_operator = "auth-role-operator"

  # db locals
  postgres_host                 = "${data.kubernetes_service.postgres.metadata[0].name}.${helm_release.postgres.namespace}.svc.cluster.local:${data.kubernetes_service.postgres.spec[0].port[0].port}"
  db_role                       = "dev-postgres"
  db_role_static                = "${local.db_role}-static"
  db_role_static_delayed        = "${local.db_role_static}-delayed"
  db_role_static_user           = "${local.db_role_static}-user"
  db_role_static_scheduled      = "${local.db_role_static}-scheduled"
  db_role_static_user_scheduled = "${local.db_role_static}-user-scheduled"
  k8s_secret_role               = "k8s-secret"

  xns_sa_count          = var.vault_enterprise ? 10 : 0
  with_xns              = var.vault_enterprise && var.with_xns
  xns_namespace         = local.with_xns ? vault_namespace.xns[0].path_fq : null
  xns_member_entity_ids = local.with_xns ? one(vault_identity_group.xns-parent[*]).member_entity_ids : []

  dev_token_policies = concat(
    [
      vault_policy.revocation.name,
      vault_policy.db.name,
      vault_policy.k8s_secrets.name,
    ],
    vault_policy.db-scheduled[*].name,
  )
}
