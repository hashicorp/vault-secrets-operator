# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "name_prefix" {
  value = local.name_prefix
}
output "auth_mount" {
  value = local.auth_mount
}
output "auth_role" {
  value = local.auth_role
}
output "kv_mount" {
  value = local.kv_mount
}
output "kv_v2_mount" {
  value = local.kv_v2_mount
}
output "app_k8s_namespace" {
  value = local.app_k8s_namespace
}
output "app_vault_namespace" {
  # For HVD: return var.vault_namespace (e.g. "admin") so the Go test can set the
  # Vault client namespace correctly. local.namespace is null for HVD since
  # the provider handles it via VAULT_NAMESPACE env var.
  value = var.vault_namespace != "" ? var.vault_namespace : local.namespace
}
output "admin_k8s_namespace" {
  value = local.admin_k8s_namespace
}

output "approle_mount" {
  value = var.use_hvd ? vault_auth_backend.approle[0].path : ""
}

output "approle_role_id" {
  value = var.use_hvd ? vault_approle_auth_backend_role.default[0].role_id : ""
}

output "approle_secret_ref" {
  value = var.use_hvd ? kubernetes_secret.approle_secretid[0].metadata[0].name : ""
}
