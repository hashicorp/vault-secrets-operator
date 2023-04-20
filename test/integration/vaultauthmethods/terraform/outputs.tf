output "role_id" {
  value = vault_approle_auth_backend_role.role.role_id
}

output "secret_id" {
  value = vault_approle_auth_backend_role_secret_id.id.*.secret_id
}

output "policy_id" {
  value = vault_policy.this.id
}