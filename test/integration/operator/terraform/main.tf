# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "2.13.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.2.0"
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

module "operator_common" {
  source                       = "../../modules/operator-common"
  deploy_operator_via_helm     = var.deploy_operator_via_helm
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = var.enable_default_connection
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address
}
