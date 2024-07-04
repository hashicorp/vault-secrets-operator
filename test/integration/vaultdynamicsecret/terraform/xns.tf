# Setup for cross namespace auth testing

# sets the group policy application to work with with cross Vault namespace auth
resource "vault_generic_endpoint" "sys-group-policy-application" {
  count = local.with_xns ? 1 : 0
  data_json = jsonencode(
    {
      group_policy_application_mode = "any"
    }
  )
  path           = "sys/config/group-policy-application"
  disable_delete = true
}

# default service account from the tenant namespace
resource "kubernetes_service_account" "xns" {
  count = local.xns_sa_count
  metadata {
    namespace = kubernetes_namespace.dev.metadata[0].name
    name      = "xns-sa-${count.index}"
    labels = {
      "x-ns" : local.with_xns
    }
  }
}

resource "vault_namespace" "xns" {
  count = local.with_xns ? 1 : 0
  path  = "${local.name_prefix}-xns"
}

# identity entity that maps to the service account name
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_name"
resource "vault_identity_entity" "xns" {
  count     = local.xns_sa_count
  namespace = local.namespace
  name      = "${kubernetes_service_account.xns[count.index].metadata[0].namespace}/${kubernetes_service_account.xns[count.index].metadata[0].name}"
}

# identity entity alias that maps to the service account name
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_name"
resource "vault_identity_entity_alias" "xns" {
  count          = local.xns_sa_count
  namespace      = local.namespace
  mount_accessor = vault_auth_backend.default.accessor
  name           = vault_identity_entity.xns[count.index].name
  canonical_id   = vault_identity_entity.xns[count.index].id
}

# parent identity group that holds all vso tenant entities
resource "vault_identity_group" "xns-parent" {
  count             = local.with_xns ? 1 : 0
  namespace         = local.namespace
  name              = "vso-tenants-parent"
  type              = "internal"
  member_entity_ids = concat(vault_identity_entity_alias.xns[*].canonical_id)
}
# identity group that provides cross namespace support when local.with_xns is true
resource "vault_identity_group" "xns" {
  count            = local.with_xns ? 1 : 0
  namespace        = local.xns_namespace
  name             = "vso-tenants"
  member_group_ids = [vault_identity_group.xns-parent[0].id]
  policies = [
    vault_policy.xns[0].name,
  ]
  type = "internal"
}

resource "vault_database_secrets_mount" "xns" {
  count                     = local.with_xns ? 1 : 0
  namespace                 = local.xns_namespace
  path                      = "${local.name_prefix}-db"
  default_lease_ttl_seconds = var.vault_db_default_lease_ttl

  postgresql {
    name              = "postgres"
    username          = "postgres"
    password          = data.kubernetes_secret.postgres.data["postgres-password"]
    connection_url    = "postgresql://{{username}}:{{password}}@${local.postgres_host}/postgres?sslmode=disable"
    verify_connection = false
    allowed_roles = [
      local.db_role,
    ]
  }
}

resource "vault_database_secret_backend_role" "xns" {
  count     = local.with_xns ? 1 : 0
  namespace = local.xns_namespace
  backend   = vault_database_secrets_mount.xns[0].path
  name      = local.db_role
  db_name   = vault_database_secrets_mount.xns[0].postgresql[0].name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]
}

resource "vault_policy" "xns" {
  count     = local.with_xns ? 1 : 0
  namespace = local.xns_namespace
  name      = "${local.auth_policy}-db"
  policy    = <<EOT
path "${vault_database_secrets_mount.xns[0].path}/creds/${vault_database_secret_backend_role.xns[0].name}" {
  capabilities = ["read"]
}
EOT
}
