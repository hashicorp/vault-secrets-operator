# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "kubernetes_cluster_name" {
  value = azurerm_kubernetes_cluster.default.name
}

output "container_repository_name" {
  value = azurerm_container_registry.default.name
}