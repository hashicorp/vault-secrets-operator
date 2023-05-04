# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "2.8.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.17.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "3.12.0"
    }
  }
}

provider "vault" {
  # Configuration options
  address = var.vault_address
  token   = var.vault_token
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

resource "kubernetes_namespace" "dev" {
  metadata {
    name = local.k8s_namespace
  }
}

resource "random_string" "prefix" {
  length  = 10
  upper   = false
  special = false
  keepers = {
    name_prefix = var.name_prefix
  }
}

resource "vault_namespace" "test" {
  count = var.vault_enterprise ? 1 : 0
  path  = "${local.name_prefix}-ns"
}

# kubernetes auth config
resource "vault_auth_backend" "default" {
  namespace = local.namespace
  path      = local.auth_mount
  type      = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "dev" {
  namespace              = vault_auth_backend.default.namespace
  backend                = vault_auth_backend.default.path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}

resource "vault_kubernetes_auth_backend_role" "dev" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.dev.backend
  role_name                        = local.auth_role
  bound_service_account_names      = ["default"]
  bound_service_account_namespaces = [kubernetes_namespace.dev.metadata[0].name]
  token_period                     = var.vault_token_period
  token_policies = [
    vault_policy.db.name,
  ]
  audience = "vault"
}

resource "helm_release" "vault-secrets-operator" {
  count            = var.deploy_operator_via_helm ? 1 : 0
  name             = "test"
  namespace        = var.operator_namespace_name
  create_namespace = true
  wait             = true
  chart            = var.operator_helm_chart_path

  # Connection Configuration
  set {
    name  = "defaultVaultConnection.enabled"
    value = "true"
  }
  set {
    name  = "defaultVaultConnection.address"
    value = var.vault_address
  }
  # Auth Method Configuration
  set {
    name  = "defaultAuthMethod.enabled"
    value = "true"
  }
  set {
    name  = "defaultAuthMethod.method"
    value = "kubernetes"
  }
  dynamic "set" {
    for_each = var.vault_enterprise ? [""] : []
    content {
      name  = "defaultAuthMethod.namespace"
      value = local.namespace
    }
  }
  set {
    name  = "defaultAuthMethod.kubernetes.role"
    value = vault_kubernetes_auth_backend_role.dev.role_name
  }
  set {
    name  = "defaultAuthMethod.kubernetes.tokenAudiences"
    value = "{${vault_kubernetes_auth_backend_role.dev.audience}}"
  }
  set {
    name  = "controller.manager.image.repository"
    value = var.operator_image_repo
  }
  set {
    name  = "controller.manager.image.tag"
    value = var.operator_image_tag
  }
  set {
    name  = "controller.manager.clientCache.persistenceModel"
    value = "direct-encrypted"
  }
  dynamic "set" {
    for_each = var.vault_enterprise ? [""] : []
    content {
      name  = "controller.manager.clientCache.storageEncryption.namespace"
      value = local.namespace
    }
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.keyName"
    value = vault_transit_secret_backend_key.cache.name
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.transitMount"
    value = vault_transit_secret_backend_key.cache.backend
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.serviceAccount"
    value = "${local.name_prefix}-operator" #kubernetes_service_account.operator.metadata[0].name
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.tokenAudiences"
    value = "{${join(",", local.token_audience)}}"
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.role"
    value = local.auth_role_operator
  }
}
