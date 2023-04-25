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
      version = "2.16.1"
    }
  }
}

locals {
  vault_image_tag        = var.vault_image_tag
  vault_image_repository = var.vault_enterprise ? var.vault_image_repo_ent : var.vault_image_repo
  vault_license          = var.vault_enterprise ? (var.vault_license != "" ? var.vault_license : file(var.vault_license_path)) : ""
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

resource "kubernetes_namespace" "demo" {
  metadata {
    name = var.k8s_namespace
  }
}

resource "kubernetes_secret" "vault_license" {
  count = var.vault_enterprise ? 1 : 0
  metadata {
    namespace = kubernetes_namespace.demo.metadata[0].name
    name      = "vault-license"
  }
  data = {
    license = local.vault_license
  }
}

resource "helm_release" "vault" {
  version          = var.vault_chart_version
  name             = "vault"
  namespace        = kubernetes_namespace.demo.metadata[0].name
  create_namespace = false
  wait             = true
  wait_for_jobs    = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"

  set {
    name  = "server.dev.enabled"
    value = "true"
  }
  set {
    name  = "server.image.repository"
    value = local.vault_image_repository
  }
  set {
    name  = "server.image.tag"
    value = local.vault_image_tag
  }
  set {
    name  = "server.logLevel"
    value = "debug"
  }
  set {
    name  = "injector.enabled"
    value = "false"
  }

  dynamic "set" {
    for_each = var.vault_enterprise ? [""] : []
    content {
      name  = "server.enterpriseLicense.secretName"
      value = kubernetes_secret.vault_license[0].metadata[0].name
    }
  }
}

resource "kubernetes_cluster_role_binding" "oidc-reviewer" {
  metadata {
    name = "oidc-reviewer-cluster-role-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:service-account-issuer-discovery"
  }
  subject {
    kind = "Group"
    name = "system:unauthenticated"
  }
}
