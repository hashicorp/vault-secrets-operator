# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

locals {
  namespace = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
  auth_role = "role1"
}
