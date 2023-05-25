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

resource "kubernetes_secret" "default-sa-secret" {
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    name      = "default-sa-secret"
    annotations = {
      "kubernetes.io/service-account.name" = data.kubernetes_service_account.default.metadata[0].name
    }
  }
  type                           = "kubernetes.io/service-account-token"
  wait_for_service_account_token = true
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
  name      = "dev"
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
  bound_service_account_names      = [data.kubernetes_service_account.default.metadata[0].name]
  bound_service_account_namespaces = [kubernetes_namespace.tenant-1.metadata[0].name]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.default.name]
  audience                         = "vault"
}

# jwt auth config
resource "vault_jwt_auth_backend" "dev" {
  namespace             = local.namespace
  path                  = "jwt"
  oidc_discovery_url    = "https://kubernetes.default.svc.cluster.local"
  oidc_discovery_ca_pem = nonsensitive(kubernetes_secret.default-sa-secret.data["ca.crt"])
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

# Create the Vault Auth Backend for AppRole
resource "vault_auth_backend" "approle" {
  namespace = local.namespace
  type      = "approle"
  path      = var.approle_mount_path
}

# Create the Vault Auth Backend Role for AppRole
resource "vault_approle_auth_backend_role" "role" {
  namespace = local.namespace
  backend   = vault_auth_backend.approle.path
  role_name = var.approle_role_name
  # role_id is auto-generated, and we use this to do the Login
  token_policies = [vault_policy.approle.name]
}

# Creates the Secret ID for the AppRole
resource "vault_approle_auth_backend_role_secret_id" "id" {
  namespace = local.namespace
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

# Kubernetes secret to hold the secretid
resource "kubernetes_secret" "secretid" {
  metadata {
    name      = "secretid"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
  data = {
    id = vault_approle_auth_backend_role_secret_id.id.secret_id
  }
}

resource "vault_policy" "approle" {
  name      = "approle"
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.kvv2.path}/*" {
  capabilities = ["read","list","update"]
}
path "auth/${vault_auth_backend.approle.path}/login" {
  capabilities = ["read","update"]
}
EOT
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
}
