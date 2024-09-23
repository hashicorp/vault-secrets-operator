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
    aws = {
      source  = "hashicorp/aws"
      version = "5.49.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "vault" {
  # Configuration options
  address = var.vault_address
  token   = var.vault_token
}

data "aws_eks_cluster" "cluster" {
  count = var.with_eks ? 1 : 0
  name  = var.cluster_name
}

provider "helm" {
  alias = "kind"
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

provider "kubernetes" {
  alias          = "kind"
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

provider "kubernetes" {
  alias                  = "eks"
  host                   = var.with_eks ? data.aws_eks_cluster.cluster[0].endpoint : ""
  cluster_ca_certificate = var.with_eks ? base64decode(data.aws_eks_cluster.cluster[0].certificate_authority[0].data) : ""
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    args        = ["eks", "get-token", "--cluster-name", var.with_eks ? data.aws_eks_cluster.cluster[0].name : ""]
    command     = "aws"
  }
}

provider "helm" {
  alias = "eks"
  kubernetes {
    host                   = var.with_eks ? data.aws_eks_cluster.cluster[0].endpoint : ""
    cluster_ca_certificate = var.with_eks ? base64decode(data.aws_eks_cluster.cluster[0].certificate_authority[0].data) : ""
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      args        = ["eks", "get-token", "--cluster-name", var.with_eks ? data.aws_eks_cluster.cluster[0].name : ""]
      command     = "aws"
    }
  }
}

module "operator_eks" {
  count = var.with_eks ? 1 : 0

  providers = {
    helm       = helm.eks
    kubernetes = kubernetes.eks
  }

  source                       = "../../modules/operator"
  deploy_operator_via_helm     = var.deploy_operator_via_helm
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = var.enable_default_connection
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address
}

module "operator_kind" {
  count = !var.with_eks ? 1 : 0

  providers = {
    helm       = helm.kind
    kubernetes = kubernetes.kind
  }

  source                       = "../../modules/operator"
  deploy_operator_via_helm     = var.deploy_operator_via_helm
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = var.enable_default_connection
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address
}
