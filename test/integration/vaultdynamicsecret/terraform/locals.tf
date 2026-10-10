# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  # common locals
  name_prefix = "${var.name_prefix}-${random_string.prefix.result}"
  # Falls back to us-east-1 if left empty (the Go test harness always passes
  # -var aws_region=<env value>, an explicit empty-string override when
  # AWS_REGION isn't set — this avoids an invalid empty AWS provider region).
  aws_region = var.aws_region != "" ? var.aws_region : "us-east-1"
  # HVD path: null — the vault provider is already scoped to the target
  # namespace via the VAULT_NAMESPACE env var (set by the test runner), so
  # resources must NOT also set an explicit namespace attribute, or the
  # provider concatenates the two into a nested (and invalid) "admin/admin".
  # Enterprise (non-HVD) path: use the auto-created vault_namespace.test child namespace.
  # Community path: no namespace.
  # Order matters: vault_namespace != "" must be checked first so that
  # vault_namespace.test[0] (count-guarded to 0 under HVD) is never evaluated.
  namespace = (
    var.vault_namespace != "" ? null :
    var.vault_enterprise ? vault_namespace.test[0].path_fq :
    null
  )

  # k8s locals
  k8s_namespace = "${local.name_prefix}-k8s-ns"

  # auth locals
  auth_mount         = "${local.name_prefix}-auth-mount"
  auth_mount_xns     = "${local.name_prefix}-auth-mount-xns"
  auth_policy        = "${local.name_prefix}-auth-policy"
  auth_role          = "auth-role"
  auth_role_xns      = "auth-role-xns"
  auth_role_operator = "auth-role-operator"

  # db locals
  # HVD path: EC2 public IP:5432 (reachable by HVD).
  # kind path: in-cluster service DNS (unchanged).
  postgres_host = (
    var.use_hvd ? "${aws_instance.postgres[0].public_ip}:5432" :
    "${data.kubernetes_service.postgres[0].metadata[0].name}.${helm_release.postgres[0].namespace}.svc.cluster.local:${data.kubernetes_service.postgres[0].spec[0].port[0].port}"
  )
  # HVD path: use the EC2 Postgres superuser password (explicit var, or an
  # auto-generated one — see local.ec2_postgres_password in postgres.tf).
  # kind path: read the password from the Helm-installed Postgres k8s Secret.
  pg_password                   = var.use_hvd ? local.ec2_postgres_password : data.kubernetes_secret.postgres[0].data["postgres-password"]
  db_role                       = "dev-postgres"
  db_role_static                = "${local.db_role}-static"
  db_role_static_delayed        = "${local.db_role_static}-delayed"
  db_role_static_user           = "${local.db_role_static}-user"
  db_role_static_scheduled      = "${local.db_role_static}-scheduled"
  db_role_static_user_scheduled = "${local.db_role_static}-user-scheduled"
  k8s_secret_role               = "k8s-secret"

  # xns_sa_count must also be guarded by !use_hvd: HVD is always Enterprise,
  # so var.vault_enterprise=true is passed for HVD runs even though with_xns
  # stays disabled. Without the use_hvd guard here, the xns.tf resources
  # (kubernetes_service_account.xns, vault_identity_entity.xns,
  # vault_identity_entity_alias.xns) would still try to create with count=10
  # and vault_identity_entity_alias.xns's mount_accessor reference would break
  # once vault_auth_backend.default is count-guarded to 0 for HVD.
  xns_sa_count          = (var.vault_enterprise && !var.use_hvd) ? 10 : 0
  with_xns              = var.vault_enterprise && var.with_xns
  xns_namespace         = local.with_xns ? vault_namespace.xns[0].path_fq : null
  xns_member_entity_ids = local.with_xns ? one(vault_identity_group.xns-parent[*]).member_entity_ids : []

  dev_token_policies = concat(
    [
      vault_policy.revocation.name,
      one(coalescelist(vault_policy.db-with-events[*].name, vault_policy.db[*].name)),
      vault_policy.db-events.name,
      vault_policy.k8s_secrets.name,
    ],
    vault_policy.db-scheduled[*].name,
  )
}
