# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

data "aws_availability_zones" "available" {}

locals {
  cluster_name = "eks-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.5.2"

  name = "eks-vpc"

  cidr = "10.0.0.0/16"
  azs  = slice(data.aws_availability_zones.available.names, 0, 3)

  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  public_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = 1
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${local.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = 1
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.2.1"

  cluster_name                   = local.cluster_name
  cluster_version                = var.kubernetes_version
  cluster_endpoint_public_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa = true
  enable_cluster_creator_admin_permissions = true

  eks_managed_node_group_defaults = {
    ami_type                   = "AL2_x86_64"
    instance_types             = ["t3.medium", "t3a.medium"]
    iam_role_attach_cni_policy = true
  }

  eks_managed_node_groups = {

    default_node_group = {
      name            = "managed_node_group"
      use_name_prefix = true

      subnet_ids = module.vpc.private_subnets

      min_size     = var.eks_node_group_instance_count
      max_size     = var.eks_node_group_instance_count
      desired_size = var.eks_node_group_instance_count

      instance_types = ["t3.medium", "t3a.medium"]

      update_config = {
        max_unavailable_percentage = 1
      }

      description = "EKS managed node group launch template"

      ebs_optimized           = true
      disable_api_termination = false
      enable_monitoring       = true

      create_iam_role          = true
      iam_role_name            = "eks-nodes-${local.cluster_name}"
      iam_role_use_name_prefix = false
      iam_role_description     = "EKS managed node group role"
      iam_role_additional_policies = {
        AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
        AmazonSSMManagedInstanceCore       = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        AmazonEBSCSIDriverPolicy           = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
      }
    }
  }
}

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_name
  depends_on = [module.eks.cluster_endpoint]
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_name
  depends_on = [module.eks.cluster_endpoint]
}

module "vso-helm" {
  source                       = "../../../modules/vso-helm"
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = var.enable_default_connection
  enable_default_auth_method   = false
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address

  manager_extra_args = [
    "-min-refresh-after-hvsa=3s",
    "-zap-log-level=6"
  ]
}

module "vault" {
  source = "../../../modules/vault"
  vault_license_path = var.vault_license_path
  k8s_namespace = var.k8s_namespace
  k8s_service_account = var.k8s_service_account
  k8s_config_context = var.k8s_config_context
  k8s_config_path = var.k8s_config_path
  vault_image_repo_ent = var.vault_image_repo_ent
  vault_image_tag_ent = var.vault_image_tag_ent
  vault_chart_version = var.vault_chart_version
}
