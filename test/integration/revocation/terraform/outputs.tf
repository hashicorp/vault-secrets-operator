# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "auth_role" {
  value = var.auth_role
}

output "policy_name" {
  value = local.policy_name
}
