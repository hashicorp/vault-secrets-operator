# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "2.11.0"
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

module "vso-helm" {
  count                            = var.deploy_operator_via_helm ? 1 : 0
  source                           = "../../modules/vso-helm"
  operator_namespace               = var.operator_namespace
  operator_image_repo              = var.operator_image_repo
  operator_image_tag               = var.operator_image_tag
  enable_default_auth_method       = var.enable_default_auth_method
  enable_default_connection        = var.enable_default_connection
  operator_helm_chart_path         = var.operator_helm_chart_path
  k8s_auth_default_mount           = local.auth_mount
  k8s_auth_default_role            = vault_kubernetes_auth_backend_role.dev.role_name
  k8s_auth_default_token_audiences = [vault_kubernetes_auth_backend_role.dev.audience]
  k8s_vault_connection_address     = var.k8s_vault_connection_address
  vault_test_namespace             = local.namespace
  client_cache_config = {
    persistence_model                = "direct-encrypted"
    revoke_client_cache_on_uninstall = false
    storage_encryption = {
      enabled                         = true
      vault_connection_ref            = ""
      namespace                       = local.namespace
      method                          = vault_auth_backend.default.type
      mount                           = vault_auth_backend.default.path
      transit_mount                   = vault_transit_secret_cache_config.cache.backend
      key_name                        = vault_transit_secret_backend_key.cache.name
      kubernetes_auth_role            = vault_kubernetes_auth_backend_role.operator.role_name
      kubernetes_auth_service_account = local.operator_service_account_name
      kubernetes_auth_token_audiences = "{${vault_kubernetes_auth_backend_role.operator.audience}}"
    }
  }
}
