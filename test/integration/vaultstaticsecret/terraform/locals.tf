# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace           = var.vault_enterprise ? vault_namespace.test[0].path_fq : null
  name_prefix         = "${var.name_prefix}-${random_string.prefix.result}"
  auth_mount          = "${local.name_prefix}-auth-mount"
  kv_mount            = "${local.name_prefix}-kv"
  kv_v2_mount         = "${local.name_prefix}-kvv2"
  app_k8s_namespace   = "${local.name_prefix}-app"
  admin_k8s_namespace = "${local.name_prefix}-admin"
  auth_role           = "auth-role"
  app_policy          = "${local.name_prefix}-app"
  vault_namespace     = "${local.name_prefix}-app"
}
