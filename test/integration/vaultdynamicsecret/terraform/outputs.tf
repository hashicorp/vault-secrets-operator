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
output "k8s_secret_path" {
  value = vault_kubernetes_secret_backend.k8s_secrets.path
}
output "k8s_secret_role" {
  value = vault_kubernetes_secret_backend_role.k8s_secrets.name
}
output "db_path" {
  value = vault_database_secrets_mount.db.path
}
output "transit_ref" {
  value = one(kubernetes_manifest.vault-auth-operator[*].manifest.metadata.name)
}
output "transit_path" {
  value = vault_mount.transit.path
}
output "transit_key_name" {
  value = vault_transit_secret_backend_key.cache.name
}
output "k8s_config_context" {
  value = var.k8s_config_context
}
output "namespace" {
  value = local.namespace
}
