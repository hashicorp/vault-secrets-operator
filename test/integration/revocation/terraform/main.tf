# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.16.1"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "3.12.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.8.0"
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

resource "kubernetes_namespace" "tenant-1" {
  metadata {
    name = var.k8s_test_namespace
  }
}

resource "kubernetes_default_service_account" "default" {
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
}

resource "kubernetes_secret" "default" {
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    name      = "test-sa-secret"
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_default_service_account.default.metadata[0].name
    }
  }
  type                           = "kubernetes.io/service-account-token"
  wait_for_service_account_token = true
}

resource "random_string" "prefix" {
  length  = 10
  upper   = false
  special = false
  keepers = {
    name_prefix = var.name_prefix
  }
}

provider "vault" {
  # Configuration options
}

resource "vault_mount" "kvv2" {
  namespace   = local.namespace
  path        = var.vault_kvv2_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_policy" "default" {
  name      = local.policy_name
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.kvv2.path}/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_namespace" "test" {
  count = var.vault_enterprise ? 1 : 0
  path  = var.vault_test_namespace
}

resource "vault_auth_backend" "default" {
  namespace = local.namespace
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
  role_name                        = var.auth_role
  bound_service_account_names      = [kubernetes_default_service_account.default.metadata[0].name]
  bound_service_account_namespaces = [kubernetes_namespace.tenant-1.metadata[0].name]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.default.name]
  audience                         = "vault"
}

# jwt auth config
resource "vault_jwt_auth_backend" "dev" {
  namespace             = local.namespace
  path                  = "jwt"
  oidc_discovery_url    = var.vault_oidc_discovery_url
  oidc_discovery_ca_pem = var.vault_oidc_ca ? nonsensitive(kubernetes_secret.default.data["ca.crt"]) : ""
}

resource "vault_jwt_auth_backend_role" "dev" {
  namespace       = vault_jwt_auth_backend.dev.namespace
  backend         = "jwt"
  role_name       = var.auth_role
  role_type       = "jwt"
  bound_audiences = ["vault"]
  user_claim      = "sub"
  token_policies  = [vault_policy.default.name]
}


# VSO Helm chart
resource "helm_release" "vault-secrets-operator" {
  name             = "test"
  namespace        = var.operator_namespace
  create_namespace = true
  wait             = true
  chart            = var.operator_helm_chart_path

  set {
    name  = "controller.manager.image.repository"
    value = var.operator_image_repo
  }
  set {
    name  = "controller.manager.image.tag"
    value = var.operator_image_tag
  }

  # Connection Configuration
  set {
    name  = "defaultVaultConnection.enabled"
    value = "true"
  }
  set {
    name  = "defaultVaultConnection.address"
    value = var.k8s_vault_connection_address
  }

  set {
    name  = "controller.manager.clientCache.preserveClientCacheOnShutDown"
    value = "false"
  }

  set {
    name  = "controller.manager.clientCache.persistenceModel"
    value = "direct-unencrypted"
  }
}
