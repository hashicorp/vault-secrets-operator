# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

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

  oidc_issuer_enabled = true

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
  name                = "${var.container_repository_prefix}${random_string.suffix.result}"
  location            = azurerm_resource_group.default.location
  resource_group_name = azurerm_resource_group.default.name
  sku                 = "Premium"
}

resource "azurerm_role_assignment" "default" {
  principal_id                     = azurerm_kubernetes_cluster.default.kubelet_identity[0].object_id
  role_definition_name             = "AcrPull"
  scope                            = azurerm_container_registry.default.id
  skip_service_principal_aad_check = true
}

resource "local_file" "env_file" {
  filename = "${path.module}/outputs.env"
  content  = <<EOT
AKS_OIDC_URL=${azurerm_kubernetes_cluster.default.oidc_issuer_url}
ACR_NAME=${azurerm_container_registry.default.name}
AKS_CLUSTER_NAME=${azurerm_kubernetes_cluster.default.name}
AZURE_RSG_NAME=${azurerm_resource_group.default.name}
AZURE_REGION="${var.region}"
IMAGE_TAG_BASE=${format("%s.azurecr.io/%s", azurerm_container_registry.default.name, var.image_tag_base)}
K8S_CLUSTER_CONTEXT="${azurerm_kubernetes_cluster.default.name}-admin"
EOT
}
