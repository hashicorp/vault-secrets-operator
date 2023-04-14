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

# jwt auth config
resource "vault_jwt_auth_backend" "dev" {
  namespace             = vault_auth_backend.default.namespace
  path                  = local.jwt_auth_mount
  oidc_discovery_url    = "https://kubernetes.default.svc.cluster.local"
}

resource "vault_jwt_auth_backend_role" "dev" {
  namespace       = vault_auth_backend.default.namespace
  backend         = local.jwt_auth_mount
  role_name       = local.auth_role
  role_type       = "jwt"
  bound_audiences = ["vault"]
  user_claim      = "https://vault/user"
  token_policies = [
    vault_policy.db.name,
  ]
}
