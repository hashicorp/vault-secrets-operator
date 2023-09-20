# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  # k8s locals
  k8s_namespace      = "${var.name_prefix}-k8s-ns"
  operator_namespace = module.vso-helm.namespace
}
