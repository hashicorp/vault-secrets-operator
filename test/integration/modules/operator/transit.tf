# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

data "kubernetes_namespace" "operator" {
  count = var.deploy_operator_via_helm ? 0 : 1
  metadata {
    name = var.operator_namespace
  }
}

# service account for the operator
resource "kubernetes_service_account" "operator" {
  metadata {
    namespace = local.operator_namespace
    name      = local.operator_service_account_name
  }
}

# transit setup for vso client cache encryption
resource "vault_mount" "transit" {
  path        = "transit"
  type        = "transit"
  description = "VSO Client Cache"
}

resource "vault_transit_secret_cache_config" "cache" {
  namespace = vault_mount.transit.namespace
  backend   = vault_mount.transit.path
  size      = 500
}

resource "vault_transit_secret_backend_key" "cache" {
  namespace        = vault_mount.transit.namespace
  backend          = vault_mount.transit.path
  name             = "vso-client-cache"
  deletion_allowed = true
}

resource "vault_policy" "operator" {
  namespace = vault_transit_secret_backend_key.cache.namespace
  name      = "operator"
  policy    = <<EOT
path "${vault_mount.transit.path}/encrypt/${vault_transit_secret_backend_key.cache.name}" {
  capabilities = ["create", "update"]
}
path "${vault_mount.transit.path}/decrypt/${vault_transit_secret_backend_key.cache.name}" {
  capabilities = ["create", "update"]
}
EOT
}

resource "kubernetes_manifest" "vault-auth-operator" {
  count = var.deploy_operator_via_helm ? 0 : 1
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "operator"
      namespace = local.operator_namespace
      labels = {
        cacheStorageEncryption = "true"
      }
    }
    spec = {
      method             = "kubernetes"
      namespace          = vault_kubernetes_auth_backend_role.operator.namespace
      mount              = vault_auth_backend.default.path
      vaultConnectionRef = one(kubernetes_manifest.vault-connection-default[*].manifest.metadata.name)
      kubernetes = {
        role           = vault_kubernetes_auth_backend_role.operator.role_name
        serviceAccount = kubernetes_service_account.operator.metadata[0].name
        audiences      = ["vault"]
      }
      storageEncryption = {
        mount   = vault_transit_secret_backend_key.cache.backend
        keyName = vault_transit_secret_backend_key.cache.name
      }
    }
  }
}

resource "vault_kubernetes_auth_backend_role" "operator" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.operator.backend
  role_name                        = local.auth_role_operator
  bound_service_account_names      = [local.operator_service_account_name]
  bound_service_account_namespaces = [var.operator_namespace]
  token_period                     = 120
  token_policies = [
    vault_policy.operator.name,
  ]
  audience = "vault"
}
