# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1



output "auth_role" {
  value = var.auth_role
}

output "policy_name" {
  value = local.policy_name
}
