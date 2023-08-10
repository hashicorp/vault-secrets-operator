# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "kubernetes_cluster_name" {
  value = azurerm_kubernetes_cluster.default.name
}

output "container_repository_name" {
  value = azurerm_container_registry.default.name
}

output "oidc_discovery_url" {
  value       = azurerm_kubernetes_cluster.default.oidc_issuer_url
  description = "AKS OIDC discovery URL"
}

output "resource_group_name" {
  value = azurerm_resource_group.default.name
}
