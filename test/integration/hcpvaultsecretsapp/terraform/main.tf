# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.16.1"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.11.0"
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

resource "kubernetes_secret" "sp" {
  metadata {
    name      = "${local.name_prefix}-sp"
    namespace = kubernetes_namespace.dev.metadata[0].name
  }
  data = {
    "clientID"     = var.hcp_client_id
    "clientSecret" = var.hcp_client_secret
  }
}

module "vso-helm" {
  count                      = var.deploy_operator_via_helm ? 1 : 0
  source                     = "../../modules/vso-helm"
  operator_namespace         = var.operator_namespace
  enable_default_auth_method = false
  enable_default_connection  = false
  operator_helm_chart_path   = var.operator_helm_chart_path
  operator_image_repo        = var.operator_image_repo
  operator_image_tag         = var.operator_image_tag
  manager_extra_args = [
    "-min-refresh-after-hvsa=3s",
    "-zap-log-level=5"
  ]
}
