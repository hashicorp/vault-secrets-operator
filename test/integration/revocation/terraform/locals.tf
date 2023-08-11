# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

locals {
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"
  policy_name = "${local.name_prefix}-dev"
  namespace   = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
}
