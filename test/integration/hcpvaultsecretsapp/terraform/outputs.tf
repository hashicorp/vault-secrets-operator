# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

output "name_prefix" {
  value = local.name_prefix
}
output "k8s_namespace" {
  value = local.k8s_namespace
}
output "sp_secret_name" {
  value = kubernetes_secret.sp.metadata[0].name
}
