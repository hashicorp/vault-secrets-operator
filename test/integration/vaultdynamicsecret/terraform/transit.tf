data "kubernetes_namespace" "operator" {
  metadata {
    name = var.operator_namespace
  }
}
# service account for the operator
resource "kubernetes_service_account" "operator" {
  metadata {
    namespace = data.kubernetes_namespace.operator.metadata[0].name
    name      = "operator"
  }
}

# transit setup for vso client cache encryption
resource "vault_mount" "transit" {
  namespace   = local.namespace
  path        = "${local.name_prefix}-transit"
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
  name      = "${local.auth_policy}-operator"
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
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultAuth"
    metadata = {
      name      = "operator"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      method             = "kubernetes"
      namespace          = vault_kubernetes_auth_backend_role.operator.namespace
      mount              = vault_auth_backend.default.path
      vaultConnectionRef = "default"
      vaultTransitRef    = "${local.name_prefix}-vso-transit"
      kubernetes = {
        role           = vault_kubernetes_auth_backend_role.operator.role_name
        serviceAccount = kubernetes_service_account.operator.metadata[0].name
        audiences      = ["vault"]
      }
    }
  }
}

resource "kubernetes_manifest" "vault-transit-operator" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultTransit"
    metadata = {
      name      = "${local.name_prefix}-vso-transit"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      namespace    = vault_kubernetes_auth_backend_role.operator.namespace
      mount        = vault_transit_secret_backend_key.cache.backend
      vaultAuthRef = kubernetes_manifest.vault-auth-operator.manifest.metadata.name
      key          = vault_transit_secret_backend_key.cache.name
    }
  }
}
resource "vault_kubernetes_auth_backend_role" "operator" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.dev.backend
  role_name                        = local.auth_role_operator
  bound_service_account_names      = [kubernetes_service_account.operator.metadata[0].name]
  bound_service_account_namespaces = [data.kubernetes_namespace.operator.metadata[0].name]
  token_period                     = 120
  token_policies = [
    vault_policy.operator.name,
  ]
  audience = "vault"
}
