# Copyright IBM Corp. 2022, 2025
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
  value = local.namespace
}
output "admin_k8s_namespace" {
  value = local.admin_k8s_namespace
}
