# Copyright (c) HashiCorp, Inc.
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
    name  = "primary.persistence.enabled"
    value = var.postgres_enable_persistence ? "true" : "false"
  }
}

resource "kubernetes_namespace" "postgres" {
  metadata {
    name = "${local.name_prefix}-postgres"
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

data "kubernetes_pod" "postgres" {
  metadata {
    namespace = helm_release.postgres.namespace
    name      = "${helm_release.postgres.name}-postgresql-0"
  }
}

resource "null_resource" "create-pg-user" {
  triggers = {
    namespace = data.kubernetes_pod.postgres.metadata[0].namespace
    pod       = data.kubernetes_pod.postgres.metadata[0].name
    password  = data.kubernetes_secret.postgres.data["postgres-password"]
    role      = local.db_role_static_user
  }
  provisioner "local-exec" {
    command = <<EOT
tries=0
until [ $tries -ge 60 ]
do
  kubectl exec -n ${self.triggers.namespace} ${self.triggers.pod} -- \
  psql postgresql://postgres:${self.triggers.password}@127.0.0.1:5432/postgres \
  -c 'CREATE ROLE "${self.triggers.role}"' && exit 0
  ((++tries))
  sleep .5
done
exit 1
EOT
  }
}

resource "null_resource" "create-pg-user-scheduled" {
  count = var.with_static_role_scheduled ? 1 : 0
  triggers = {
    namespace = data.kubernetes_pod.postgres.metadata[0].namespace
    pod       = data.kubernetes_pod.postgres.metadata[0].name
    password  = data.kubernetes_secret.postgres.data["postgres-password"]
    role      = local.db_role_static_user_scheduled
  }
  provisioner "local-exec" {
    command = <<EOT
tries=0
until [ $tries -ge 60 ]
do
  kubectl exec -n ${self.triggers.namespace} ${self.triggers.pod} -- \
  psql postgresql://postgres:${self.triggers.password}@127.0.0.1:5432/postgres \
  -c 'CREATE ROLE "${self.triggers.role}"' && exit 0
  ((++tries))
  sleep .5
done
exit 1
EOT
  }
}


resource "vault_database_secrets_mount" "db" {
  namespace                 = local.namespace
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
      local.db_role_static,
      # optionally created since vault 1.14 does not support scheduled static roles.
      local.db_role_static_scheduled,
    ]
  }
}

resource "vault_database_secret_backend_role" "postgres" {
  namespace = local.namespace
  backend   = vault_database_secrets_mount.db.path
  name      = local.db_role
  db_name   = vault_database_secrets_mount.db.postgresql[0].name
  creation_statements = [
    "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
    "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";",
  ]
}

resource "vault_database_secret_backend_static_role" "postgres" {
  namespace           = local.namespace
  backend             = vault_database_secrets_mount.db.path
  name                = local.db_role_static
  db_name             = vault_database_secrets_mount.db.postgresql[0].name
  username            = local.db_role_static_user
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
  rotation_period     = 10
  depends_on = [
    null_resource.create-pg-user,
  ]
}

resource "vault_database_secret_backend_static_role" "postgres-scheduled" {
  count               = var.with_static_role_scheduled ? 1 : 0
  namespace           = local.namespace
  backend             = vault_database_secrets_mount.db.path
  name                = local.db_role_static_scheduled
  db_name             = vault_database_secrets_mount.db.postgresql[0].name
  username            = local.db_role_static_user_scheduled
  rotation_statements = ["ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
  rotation_schedule   = "*/1 * * * *"
  rotation_window     = 3600
  depends_on = [
    null_resource.create-pg-user,
  ]
}
resource "vault_policy" "db" {
  namespace = local.namespace
  name      = "${local.auth_policy}-db"
  policy    = <<EOT
path "${vault_database_secrets_mount.db.path}/creds/${vault_database_secret_backend_role.postgres.name}" {
  capabilities = ["read"]
}
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres.name}" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "db-scheduled" {
  count     = var.with_static_role_scheduled ? 1 : 0
  namespace = local.namespace
  name      = "${local.auth_policy}-db-scheduled"
  policy    = <<EOT
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres-scheduled[0].name}" {
  capabilities = ["read"]
}
EOT
}
