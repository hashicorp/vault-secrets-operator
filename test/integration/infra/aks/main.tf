# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

resource "azurerm_resource_group" "default" {
  name     = "rg-${random_string.suffix.result}"
  location = var.region
}

resource "azurerm_kubernetes_cluster" "default" {
  name                = "aks-${random_string.suffix.result}"
  location            = azurerm_resource_group.default.location
  resource_group_name = azurerm_resource_group.default.name

  kubernetes_version = var.kubernetes_version
  dns_prefix         = "k8s-${random_string.suffix.result}"

  default_node_pool {
    name            = "default"
    node_count      = 1
    vm_size         = "Standard_D2_v2"
    os_sku          = "Mariner"
    os_disk_size_gb = 50
  }

  identity {
    type = "SystemAssigned"
  }

  tags = {
    name        = "alliances-aks-${random_string.suffix.result}"
    environment = "Demo"
  }
}

resource "azurerm_container_registry" "default" {
  name                = var.container_repository_name
  resource_group_name = azurerm_resource_group.default.name
  location            = azurerm_resource_group.default.location
  sku                 = "Premium"
}

resource "azurerm_role_assignment" "default" {
  principal_id                     = azurerm_kubernetes_cluster.default.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.default.id
  skip_service_principal_aad_check = true
}