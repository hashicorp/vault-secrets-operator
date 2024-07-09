# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "name_prefix" {
  value = local.name_prefix
}
output "k8s_namespace" {
  value = local.k8s_namespace
}
output "auth_mount" {
  value = local.auth_mount
}
output "auth_policy" {
  value = local.auth_policy
}
output "auth_role" {
  value = local.auth_role
}
output "auth_role_operator" {
  value = local.auth_role_operator
}
output "db_role" {
  value = local.db_role
}
output "db_role_static" {
  value = local.db_role_static
}
output "db_role_static_user" {
  value = local.db_role_static_user
}
output "db_role_static_scheduled" {
  value = local.db_role_static_scheduled
}
output "db_role_static_user_scheduled" {
  value = local.db_role_static_user_scheduled
}
output "k8s_secret_path" {
  value = vault_kubernetes_secret_backend.k8s_secrets.path
}
output "k8s_secret_role" {
  value = vault_kubernetes_secret_backend_role.k8s_secrets.name
}
output "db_path" {
  value = vault_database_secrets_mount.db.path
}
output "k8s_config_context" {
  value = var.k8s_config_context
}
output "namespace" {
  value = local.namespace
}

output "static_rotation_period" {
  value = vault_database_secret_backend_static_role.postgres.rotation_period
}

output "default_lease_ttl_seconds" {
  value = vault_database_secrets_mount.db.default_lease_ttl_seconds
}

output "non_renewable_k8s_token_ttl" {
  value = vault_kubernetes_secret_backend_role.k8s_secrets.token_default_ttl
}

output "xns_k8s_sas" {
  value = concat(kubernetes_service_account.xns[*].metadata[0].name)
}

output "xns_vault_ns" {
  value = local.xns_namespace
}

output "with_xns" {
  value = local.with_xns
}

output "xns_member_entity_ids" {
  value = local.xns_member_entity_ids
}
