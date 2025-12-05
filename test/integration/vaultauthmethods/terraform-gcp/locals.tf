# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace = var.vault_enterprise ? var.vault_test_namespace : null
}
