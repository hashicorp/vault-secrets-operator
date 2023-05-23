# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "auth_role" {
  value = var.auth_role
}

output "role_id" {
  description = "role_id of the approle role"
  value       = vault_approle_auth_backend_role.role.role_id
}
