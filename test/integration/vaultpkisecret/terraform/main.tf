# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.13.1"
    }
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

resource "kubernetes_namespace" "app" {
  metadata {
    name = local.app_k8s_namespace
  }
}

resource "kubernetes_secret" "pki1" {
  metadata {
    name      = "pki1"
    namespace = kubernetes_namespace.app.metadata[0].name
  }
}

provider "vault" {
  # Configuration options
}

resource "random_string" "prefix" {
  length  = 16
  upper   = false
  special = false
  keepers = {
    name_prefix = var.name_prefix
  }
}

// Vault Enterprise setup
resource "vault_namespace" "app" {
  count = var.vault_enterprise ? 1 : 0
  path  = local.vault_namespace
}

resource "vault_mount" "pki" {
  namespace                 = local.namespace
  path                      = local.pki_mount
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role" {
  namespace        = vault_mount.pki.namespace
  backend          = vault_mount.pki.path
  name             = local.pki_role
  ttl              = 3600
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com"]
  allow_subdomains = true
  allowed_uri_sans = ["uri1.example.com", "uri2.example.com"]
  allowed_user_ids = ["12345", "67890"]
}

resource "vault_pki_secret_backend_root_cert" "test" {
  namespace            = vault_mount.pki.namespace
  backend              = vault_mount.pki.path
  type                 = "internal"
  common_name          = "Root CA"
  ttl                  = "315360000"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "My OU"
  organization         = "My organization"
}

resource "vault_auth_backend" "default" {
  namespace = local.namespace
  path      = local.auth_mount
  type      = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "default" {
  namespace              = vault_auth_backend.default.namespace
  backend                = vault_auth_backend.default.path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}

resource "vault_kubernetes_auth_backend_role" "default" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = local.auth_role
  bound_service_account_names      = ["default"]
  bound_service_account_namespaces = [kubernetes_namespace.app.metadata[0].name]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.default.name]
  audience                         = "vault"
}

resource "vault_policy" "default" {
  name      = local.app_policy
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.pki.path}/*" {
  capabilities = ["read", "create", "update"]
}
EOT
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
  k8s_auth_default_mount           = vault_kubernetes_auth_backend_role.default.backend
  k8s_auth_default_role            = vault_kubernetes_auth_backend_role.default.role_name
  k8s_auth_default_token_audiences = [vault_kubernetes_auth_backend_role.default.audience]
  k8s_vault_connection_address     = var.k8s_vault_connection_address
  vault_test_namespace             = var.vault_test_namespace
}
