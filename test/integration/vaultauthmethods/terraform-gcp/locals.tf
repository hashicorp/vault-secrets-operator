# Copyright IBM Corp. 2024, 2026
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace = var.vault_enterprise ? var.vault_test_namespace : null
}
