# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  namespace         = var.vault_enterprise ? vault_namespace.app[0].path_fq : null
  name_prefix       = "${var.name_prefix}-${random_string.prefix.result}"
  auth_mount        = "${local.name_prefix}-auth-mount"
  auth_policy       = "${local.name_prefix}-auth-policy"
  pki_mount         = "${local.name_prefix}-pki"
  auth_role         = "auth-role"
  pki_role          = "pki-role"
  app_k8s_namespace = "${local.name_prefix}-app"
  vault_namespace   = "${local.name_prefix}-app"
  app_policy        = "${local.name_prefix}-app"
}
