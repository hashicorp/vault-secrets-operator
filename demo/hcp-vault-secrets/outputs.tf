# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "name_prefix" {
  value = var.name_prefix
}
output "k8s_namespace" {
  value = local.k8s_namespace
}
output "sp_secret_name" {
  value = kubernetes_secret.sp.metadata[0].name
}
output "demo_script" {
  value = "./demo.sh"
}
