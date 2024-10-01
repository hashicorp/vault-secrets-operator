# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_prometheus_workspace" "workspace" {
  alias = "workspace"

  tags = {
    Name = "${var.cluster_name}-prometheus-workspace"
  }
}

data "aws_eks_cluster" "cluster" {
  name  = var.cluster_name
}


resource "helm_release" "kube-prometheus" {
  name             = "kube-prometheus"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = var.prometheus_namespace
  wait             = true
  wait_for_jobs    = true
  version          = "62.7.0"
#  values           = [
#    file("values.yaml")
#  ]
  timeout = 2000
}
