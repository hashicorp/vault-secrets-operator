# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_prometheus_workspace" "workspace" {
  alias = "workspace"

  tags = {
    Name = "${var.cluster_name}-prometheus-workspace"
  }
}

data "aws_eks_cluster" "cluster" {
  count = var.with_eks ? 1 : 0
  name  = var.cluster_name
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

resource "helm_release" "kube-prometheus" {
#  count            = true ? 1 : 0
  name             = "kube-prometheus"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = "kube-prometheus"
  create_namespace = true
  wait             = true
  wait_for_jobs    = true
  version          = "62.7.0"
#  values           = [
#    file("values.yaml")
#  ]
  timeout = 2000
}
