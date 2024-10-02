# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "vault_root_token" {
  value = enos_vault_init.leader[0].root_token
}

output "vault_pods" {
  value = data.enos_kubernetes_pods.vault_pods[0].pods
}