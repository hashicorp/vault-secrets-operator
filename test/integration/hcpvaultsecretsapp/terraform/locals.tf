# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

locals {
  # common locals
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"

  # k8s locals
  k8s_namespace = "${local.name_prefix}-k8s-ns"
}
