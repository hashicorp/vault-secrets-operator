# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "helm_release" "postgres" {
  count            = var.use_hvd ? 0 : 1
  namespace        = kubernetes_namespace.postgres[0].metadata[0].name
  name             = "postgres"
  create_namespace = false
  wait             = true
  chart            = var.chart_postgres
}

resource "kubernetes_namespace" "postgres" {
  count = var.use_hvd ? 0 : 1
  metadata {
    name = "${local.name_prefix}-postgres"
  }
}

data "kubernetes_secret" "postgres" {
  count = var.use_hvd ? 0 : 1
  metadata {
    namespace = helm_release.postgres[0].namespace
    name      = var.postgres_secret_name
  }
}

# canary datasource: ensures that the postgres service exists, and provides the configured port.
data "kubernetes_service" "postgres" {
  count = var.use_hvd ? 0 : 1
  metadata {
    namespace = helm_release.postgres[0].namespace
    name      = "${helm_release.postgres[0].name}-postgresql"
  }
}

data "kubernetes_pod" "postgres" {
  count = var.use_hvd ? 0 : 1
  metadata {
    namespace = helm_release.postgres[0].namespace
    name      = "${helm_release.postgres[0].name}-postgresql-0"
  }
}

resource "null_resource" "create-pg-user" {
  count = var.use_hvd ? 0 : 1
  triggers = {
    namespace = data.kubernetes_pod.postgres[0].metadata[0].namespace
    pod       = data.kubernetes_pod.postgres[0].metadata[0].name
    password  = data.kubernetes_secret.postgres[0].data["postgres-password"]
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
  count = (var.with_static_role_scheduled && !var.use_hvd) ? 1 : 0
  triggers = {
    namespace = data.kubernetes_pod.postgres[0].metadata[0].namespace
    pod       = data.kubernetes_pod.postgres[0].metadata[0].name
    password  = data.kubernetes_secret.postgres[0].data["postgres-password"]
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
    password          = local.pg_password
    connection_url    = "postgresql://{{username}}:{{password}}@${local.postgres_host}/postgres?sslmode=disable"
    verify_connection = false
    allowed_roles = [
      local.db_role,
      local.db_role_static,
      local.db_role_static_delayed,
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
  rotation_period     = 30
  depends_on = [
    null_resource.create-pg-user,
    null_resource.create-pg-user-ec2,
  ]
}

resource "vault_database_secret_backend_static_role" "postgres-delayed" {
  namespace           = local.namespace
  backend             = vault_database_secrets_mount.db.path
  name                = local.db_role_static_delayed
  db_name             = vault_database_secrets_mount.db.postgresql[0].name
  username            = local.db_role_static_user
  rotation_statements = ["SELECT pg_sleep(3); ALTER USER \"{{name}}\" WITH PASSWORD '{{password}}';"]
  rotation_period     = 30
  depends_on = [
    null_resource.create-pg-user,
    null_resource.create-pg-user-ec2,
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
    # NOTE: this static role uses db_role_static_user_scheduled (not
    # db_role_static_user), so it must depend on the *-scheduled OS-user
    # creation resources, not the base create-pg-user/create-pg-user-ec2.
    null_resource.create-pg-user-scheduled,
    null_resource.create-pg-user-scheduled-ec2,
  ]
}
resource "vault_policy" "db" {
  count     = var.use_events ? 0 : 1
  namespace = local.namespace
  name      = "${local.auth_policy}-db"
  policy    = <<EOT
path "${vault_database_secrets_mount.db.path}/creds/${vault_database_secret_backend_role.postgres.name}" {
  capabilities = ["read"]
}
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres.name}" {
  capabilities = ["read"]
}
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres-delayed.name}" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "db-with-events" {
  count     = var.use_events ? 1 : 0
  namespace = local.namespace
  name      = "${local.auth_policy}-db"
  policy    = <<EOT
# The dynamic creds path is both read (to fetch credentials) and subscribed to
# (for lease* events). Because Vault ACLs use the most-specific matching path
# with no capability merge across path patterns, this exact-path rule must grant
# "subscribe" with lease* itself, otherwise it shadows the "${vault_database_secrets_mount.db.path}/*"
# glob subscribe grant below and lease events are never delivered.
path "${vault_database_secrets_mount.db.path}/creds/${vault_database_secret_backend_role.postgres.name}" {
  capabilities = ["read", "subscribe"]
  subscribe_event_types = ["lease*"]
}
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres.name}" {
  capabilities = ["read"]
}
path "${vault_database_secrets_mount.db.path}/static-creds/${vault_database_secret_backend_static_role.postgres-delayed.name}" {
  capabilities = ["read"]
}
path "${vault_database_secrets_mount.db.path}/*" {
  capabilities = ["subscribe"]
  subscribe_event_types = ["database*", "lease*"]
}

path "sys/events/subscribe/database*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_policy" "db-events" {
  namespace = local.namespace
  name      = "${local.auth_policy}-db-events"
  policy    = <<EOT
path "${vault_database_secrets_mount.db.path}/*" {
  capabilities = ["read", "list", "subscribe"]
  subscribe_event_types = ["database*", "lease*"]
}

path "sys/events/subscribe/database*" {
  capabilities = ["read"]
}

path "sys/leases/*" {
  capabilities = ["subscribe"]
  subscribe_event_types = ["lease*"]
}

path "sys/events/subscribe/lease*" {
  capabilities = ["read"]
}

# Required for GetMountType: resolves the Vault plugin type for a mount path
# so that the operator subscribes to the correct event stream.
path "sys/mounts/*" {
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

# ─────────────────────────────────────────────────────────────────────────
# HVD only: EC2-hosted PostgreSQL.
#
# HVD is an external cloud service and cannot reach the in-cluster Postgres
# Helm release (private pod DNS). This EC2 instance is a publicly-reachable
# stand-in, fully managed by Terraform in the same working directory/state
# as everything else here — `terraform destroy` tears it down exactly like
# any other resource in this file, no separate cleanup mechanism needed.
#
# vault_database_secrets_mount.db's connection_url points at this instance's
# public IP (see local.postgres_host in locals.tf) once use_hvd=true.
# ─────────────────────────────────────────────────────────────────────────

# Auto-discovers the latest EDR-compliant hc-base AL2023 AMI when
# var.ec2_ami_id is left empty, so callers don't need to hunt down an
# AMI ID (which is region/owner-account specific and rotates over time).
data "aws_ami" "postgres_base" {
  count       = (var.use_hvd && var.ec2_ami_id == "") ? 1 : 0
  most_recent = true
  owners      = ["888995627335"] # hc-base AMI owner account

  filter {
    name   = "name"
    values = ["hc-base-al2023-x86_64-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  ec2_ami_id = var.ec2_ami_id != "" ? var.ec2_ami_id : (
    var.use_hvd ? data.aws_ami.postgres_base[0].id : ""
  )
}

# Auto-generates a Postgres superuser password when var.ec2_postgres_password
# is left empty. special=false avoids characters (', ", $, \) that would
# need extra escaping inside the psql/shell commands below.
resource "random_password" "postgres" {
  count            = (var.use_hvd && var.ec2_postgres_password == "") ? 1 : 0
  length           = 24
  special          = false
  override_special = ""
}

locals {
  ec2_postgres_password = var.ec2_postgres_password != "" ? var.ec2_postgres_password : (
    var.use_hvd ? random_password.postgres[0].result : ""
  )
}

# Auto-detects the test runner's current public IP when var.ssh_ingress_cidr
# is left empty, so SSH access doesn't break if the runner's IP changes
# between test runs (a stale hardcoded CIDR caused a connection timeout
# earlier during development).
data "http" "current_ip" {
  count = (var.use_hvd && var.ssh_ingress_cidr == "") ? 1 : 0
  url   = "https://checkip.amazonaws.com"
}

locals {
  ssh_ingress_cidr = var.ssh_ingress_cidr != "" ? var.ssh_ingress_cidr : (
    var.use_hvd ? "${trimspace(data.http.current_ip[0].response_body)}/32" : ""
  )
  # Falls back to unrestricted egress access if left empty (e.g. the Go test
  # harness always passes -var hvd_egress_cidr=<env value>, which is an
  # explicit empty string override when the env var isn't set — this
  # short-circuits back to a safe default rather than an invalid "" CIDR).
  hvd_egress_cidr = var.hvd_egress_cidr != "" ? var.hvd_egress_cidr : "0.0.0.0/0"
  # Same rationale as above: an explicit empty-string override from the Go
  # test harness must not clobber the sensible t3.small default.
  ec2_instance_type = var.ec2_instance_type != "" ? var.ec2_instance_type : "t3.small"
}

# Generated fresh per test run — never touches a local ~/.ssh file, so this
# works identically on any machine (laptop or CI runner) with no local
# prerequisite key pair.
resource "tls_private_key" "postgres_ssh" {
  count     = var.use_hvd ? 1 : 0
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "postgres" {
  count      = var.use_hvd ? 1 : 0
  key_name   = "${local.name_prefix}-postgres-key"
  public_key = tls_private_key.postgres_ssh[0].public_key_openssh
}

resource "aws_security_group" "postgres" {
  count       = var.use_hvd ? 1 : 0
  name        = "${local.name_prefix}-postgres"
  description = "Allow Postgres from HVD egress and SSH from the test runner"

  ingress {
    description = "Postgres from HVD"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [local.hvd_egress_cidr]
  }

  ingress {
    description = "SSH from the test runner"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [local.ssh_ingress_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "postgres" {
  count                       = var.use_hvd ? 1 : 0
  ami                         = local.ec2_ami_id
  instance_type               = local.ec2_instance_type
  key_name                    = aws_key_pair.postgres[0].key_name
  vpc_security_group_ids      = [aws_security_group.postgres[0].id]
  associate_public_ip_address = true

  tags = {
    Name      = "${local.name_prefix}-postgres"
    CreatedBy = "vso-integration-test"
  }

  timeouts {
    create = "10m"
  }

  # Installs and configures PostgreSQL 15 for remote access. Runs on every
  # test run — no AMI-baked Postgres, so the AMI only needs to be an
  # EDR-compliant hc-base Amazon Linux 2023 base image with dnf available.
  provisioner "remote-exec" {
    inline = [
      "sudo dnf install -y postgresql15-server postgresql15",
      "sudo postgresql-setup --initdb",
      "sudo systemctl enable --now postgresql",
      "sudo -u postgres psql -c \"ALTER USER postgres WITH PASSWORD '${local.ec2_postgres_password}';\"",
      "echo \"host all all 0.0.0.0/0 md5\" | sudo tee -a /var/lib/pgsql/data/pg_hba.conf",
      "echo \"listen_addresses = '*'\" | sudo tee -a /var/lib/pgsql/data/postgresql.conf",
      "sudo systemctl restart postgresql",
    ]

    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = tls_private_key.postgres_ssh[0].private_key_pem
      host        = self.public_ip
    }
  }
}

# Creates the static-role OS user on the EC2 Postgres instance, mirroring
# what null_resource.create-pg-user does via kubectl exec for the kind path.
resource "null_resource" "create-pg-user-ec2" {
  count      = var.use_hvd ? 1 : 0
  depends_on = [aws_instance.postgres]

  triggers = {
    instance_id = aws_instance.postgres[0].id
    role        = local.db_role_static_user
  }

  provisioner "remote-exec" {
    inline = [
      "sudo -u postgres psql -c 'CREATE ROLE \"${local.db_role_static_user}\"'",
    ]

    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = tls_private_key.postgres_ssh[0].private_key_pem
      host        = aws_instance.postgres[0].public_ip
    }
  }
}

# Creates the scheduled static-role OS user on the EC2 Postgres instance,
# mirroring what null_resource.create-pg-user-scheduled does via kubectl exec
# for the kind path. Without this, vault_database_secret_backend_static_role
# "postgres-scheduled" fails with "role ... does not exist" under HVD.
resource "null_resource" "create-pg-user-scheduled-ec2" {
  count      = (var.with_static_role_scheduled && var.use_hvd) ? 1 : 0
  depends_on = [aws_instance.postgres]

  triggers = {
    instance_id = aws_instance.postgres[0].id
    role        = local.db_role_static_user_scheduled
  }

  provisioner "remote-exec" {
    inline = [
      "sudo -u postgres psql -c 'CREATE ROLE \"${local.db_role_static_user_scheduled}\"'",
    ]

    connection {
      type        = "ssh"
      user        = "ec2-user"
      private_key = tls_private_key.postgres_ssh[0].private_key_pem
      host        = aws_instance.postgres[0].public_ip
    }
  }
}
