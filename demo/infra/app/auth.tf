# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

# kubernetes auth config
resource "vault_auth_backend" "default" {
  namespace = local.namespace
  path      = local.auth_mount
  type      = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "default" {
  namespace              = vault_auth_backend.default.namespace
  backend                = vault_auth_backend.default.path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}

# kubernetes auth roles
resource "vault_kubernetes_auth_backend_role" "default" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = local.auth_role
  bound_service_account_names      = ["default"]
  bound_service_account_namespaces = local.bound_service_account_namespaces
  token_period                     = 120
  token_policies                   = local.default_token_policies
  audience                         = "vault"
}
# operator role used for transit encrypt/decrypt of VSO's Vault client cache
resource "vault_kubernetes_auth_backend_role" "operator" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = local.auth_role_operator
  bound_service_account_names      = [kubernetes_service_account.operator.metadata[0].name]
  bound_service_account_namespaces = [data.kubernetes_namespace.operator.metadata[0].name]
  token_period                     = 120
  token_policies = [
    vault_policy.operator.name,
  ]
  audience = "vault"
}
