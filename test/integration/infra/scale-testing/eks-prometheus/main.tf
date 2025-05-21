# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "aws_prometheus_workspace" "scale_testing" {
  alias = "scale_testing"

  tags = {
    Name = "${var.cluster_name}-prometheus-workspace"
  }
}

#resource "kubernetes_namespace" "prometheus" {
#  metadata {
#    name = var.prometheus_k8s_namespace
#  }
#}

#resource "kubernetes_service_account" "amsp_ingest" {
#  metadata {
#    namespace = kubernetes_namespace.prometheus.metadata.name
#    name = var.amsp_ingest_sa
#  }
#}

resource "helm_release" "kube-prometheus" {
  name             = "kube-prometheus"
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  namespace        = var.prometheus_k8s_namespace
  create_namespace = true
  wait             = true
  wait_for_jobs    = true
  version          = "62.7.0"
  values           = [
    templatefile("${path.module}/../values.yaml", {
      amsp_ingest_sa = var.amsp_ingest_sa
      iam_proxy_prometheus_role_arn = var.iam_proxy_prometheus_role_arn
      region = var.region
      workspace_id = aws_prometheus_workspace.scale_testing.id
    })
  ]
  timeout = 2000
}
