# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

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

resource "kubernetes_namespace" "tenant-2" {
  metadata {
    name = format("%s-test", var.k8s_test_namespace)
  }
}

resource "kubernetes_secret" "secretkv" {
  metadata {
    name      = "secretkv"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
}

resource "kubernetes_secret" "secretkvv2" {
  metadata {
    name      = "secretkvv2"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
}

provider "vault" {
  # Configuration options
}

locals {
  namespace = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
}

resource "vault_mount" "kv" {
  namespace   = local.namespace
  path        = var.vault_kv_mount_path
  type        = "kv"
  options     = { version = "1" }
  description = "KV Version 1 secret engine mount"
}

resource "vault_mount" "kvv2" {
  namespace   = local.namespace
  path        = var.vault_kvv2_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
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
  role_name                        = "role1"
  bound_service_account_names      = ["default"]
  bound_service_account_namespaces = [kubernetes_namespace.tenant-1.metadata[0].name]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.default.name]
  audience                         = "vault"
}

resource "vault_policy" "default" {
  name      = "dev"
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.kvv2.path}/*" {
  capabilities = ["read"]
}

path "${vault_mount.kv.path}/*" {
  capabilities = ["read"]
}
EOT
}

resource "helm_release" "vault-secrets-operator" {
  count            = var.deploy_operator_via_helm ? 1 : 0
  name             = "test"
  namespace        = var.operator_namespace
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
    value = var.k8s_vault_connection_address
  }
  # Auth Method Configuration
  set {
    name  = "defaultAuthMethod.enabled"
    value = "true"
  }
  set {
    name  = "defaultAuthMethod.namespace"
    value = var.vault_test_namespace
  }
  set {
    name  = "defaultAuthMethod.kubernetes.role"
    value = vault_kubernetes_auth_backend_role.default.role_name
  }
  set {
    name  = "defaultAuthMethod.kubernetes.tokenAudiences"
    value = "{${vault_kubernetes_auth_backend_role.default.audience}}"
  }
  set {
    name  = "controller.manager.image.repository"
    value = var.operator_image_repo
  }
  set {
    name  = "controller.manager.image.tag"
    value = var.operator_image_tag
  }
}
