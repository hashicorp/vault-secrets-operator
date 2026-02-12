# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

output "auth_role" {
  value = var.auth_role
}

output "role_id" {
  description = "role_id of the approle role"
  value       = vault_approle_auth_backend_role.role.role_id
}

output "vault_policy" {
  description = "vault policy default"
  value       = vault_policy.default.name
}
