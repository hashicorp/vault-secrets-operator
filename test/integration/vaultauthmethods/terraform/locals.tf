# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
}
