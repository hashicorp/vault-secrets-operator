# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

resource "helm_release" "postgres" {
  namespace        = kubernetes_namespace.postgres.metadata[0].name
  name             = "postgres"
  create_namespace = false
  wait             = true
  wait_for_jobs    = true

  # ref: https://github.com/bitnami/charts/issues/30582#issuecomment-2494545610
  repository = "oci://registry-1.docker.io/bitnamicharts"
  chart      = "postgresql"
  version    = "16.2.2"

  set {
    name  = "auth.audit.logConnections"
    value = "true"
  }
  set {
    name  = "auth.audit.logConnections"
    value = "true"
  }
}

resource "kubernetes_namespace" "postgres" {
  metadata {
    name = "postgres"
  }
}

data "kubernetes_secret" "postgres" {
  metadata {
    namespace = helm_release.postgres.namespace
    name      = var.postgres_secret_name
  }
}

# canary datasource: ensures that the postgres service exists, and provides the configured port.
data "kubernetes_service" "postgres" {
  metadata {
    namespace = helm_release.postgres.namespace
    name      = "${helm_release.postgres.name}-${helm_release.postgres.chart}"
  }
}

resource "vault_database_secrets_mount" "db" {
  namespace                 = local.namespace
  path                      = "${local.name_prefix}-db"
  default_lease_ttl_seconds = 300

  postgresql {
    name              = "postgres"
    username          = "postgres"
    password          = data.kubernetes_secret.postgres.data["postgres-password"]
    connection_url    = "postgresql://{{username}}:{{password}}@${local.postgres_host}/postgres?sslmode=disable"
    verify_connection = false
    allowed_roles = [
      var.db_role,
    ]
  }
}

resource "vault_database_secret_backend_role" "postgres" {
  namespace = local.namespace
  backend   = vault_database_secrets_mount.db.path
  name      = var.db_role
  db_name   = vault_database_secrets_mount.db.postgresql[0].name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]
}

resource "vault_policy" "db" {
  namespace = local.namespace
  name      = "${local.auth_policy}-db"
  policy    = <<EOT
path "${vault_database_secrets_mount.db.path}/creds/${vault_database_secret_backend_role.postgres.name}" {
  capabilities = ["read"]
}
EOT
}
