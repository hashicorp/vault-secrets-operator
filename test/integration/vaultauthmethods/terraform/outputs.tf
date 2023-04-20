# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "role_id" {
  description = "role_id of the approle role"
  value       = vault_approle_auth_backend_role.role.role_id
}

output "secret_id" {
  description = "secret_id of the approle role"
  sensitive   = true
  value       = vault_approle_auth_backend_role_secret_id.id.secret_id
}
