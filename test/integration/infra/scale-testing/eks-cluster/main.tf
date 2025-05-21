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

# Amazon EKS cluster must have an Amazon EBS CSI driver installed to setup ingestion from Prometheus server
# See https://docs.aws.amazon.com/prometheus/latest/userguide/AMP-onboard-ingest-metrics-new-Prometheus.html
# The EBS CSI driver requires IAM permissions to talk to Amazon EBS to manage the volume on user's behalf. The following module
# https://github.com/terraform-aws-modules/terraform-aws-iam/tree/v5.44.1/modules/iam-role-for-service-accounts-eks
# configures the exact IAM role for the EBS CSI driver.
# This module is designed to use in conjunction with eks module for easy integration
module "ebs_csi_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.44.1"

  role_name             = "${module.eks.cluster_name}-ebs-csi"
  attach_ebs_csi_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      # the driver Deployment service account is ebs-csi-controller-sa by default
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

locals {
  # K8s service account
  amsp_ingest_sa = "amsp-ingest"
  prometheus_k8s_namespace = "kube-prometheus"
}

module "amazon_managed_service_prometheus_irsa_role" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "5.44.1"

  role_name      = "${module.eks.cluster_name}-amazon-managed-service-prometheus"
  attach_amazon_managed_service_prometheus_policy = true

  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["${local.prometheus_k8s_namespace}:${local.amsp_ingest_sa}"]
    }
  }
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.2.1"

  cluster_name                   = local.cluster_name
  cluster_version                = var.kubernetes_version
  cluster_endpoint_public_access = true

  cluster_addons = {
    aws-ebs-csi-driver = {
      service_account_role_arn = module.ebs_csi_irsa_role.iam_role_arn
      most_recent = true
   }
  }

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  enable_irsa                              = true
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
  name       = module.eks.cluster_name
  depends_on = [module.eks.cluster_endpoint]
}

data "aws_eks_cluster_auth" "cluster" {
  name       = module.eks.cluster_name
  depends_on = [module.eks.cluster_endpoint]
}

resource "local_file" "env_file" {
  filename = "${path.module}/outputs.env"
  content  = <<EOT
EKS_OIDC_URL=${module.eks.cluster_oidc_issuer_url}
EKS_CLUSTER_NAME=${module.eks.cluster_name}
AWS_REGION=${var.region}
K8S_CLUSTER_CONTEXT=${module.eks.cluster_arn}
AMSP_INGEST_SA=${local.amsp_ingest_sa}
PROMETHEUS_K8S_NAMESPACE=${local.prometheus_k8s_namespace}
IAM_PROXY_PROMETHEUS_ROLE_ARN=${module.amazon_managed_service_prometheus_irsa_role.iam_role_arn}
EOT
}