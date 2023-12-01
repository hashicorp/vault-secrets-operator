# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace = var.vault_enterprise ? var.vault_test_namespace : null
}
