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
  path        = "transit"
  type        = "transit"
  description = "VSO Client Cache"
  #default_lease_ttl_seconds = 3600
  #max_lease_ttl_seconds     = 86400
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
      vaultTransitRef    = "vso-transit"
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
      name      = "vso-transit"
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
