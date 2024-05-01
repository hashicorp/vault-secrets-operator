# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "helm_release" "argo_rollouts" {
  namespace        = "argo"
  create_namespace = true
  name             = "argo-rollouts"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-rollouts"
  version          = "2.35.1"
}
