# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "k8s_namespace" {
  value = local.k8s_namespace
}
output "auth_role_operator" {
  value = local.auth_role_operator
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
  value = local.operator_namespace
}
