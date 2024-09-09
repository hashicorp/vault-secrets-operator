# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

module "vault" {
  source               = "../../../../modules/vault"
  vault_license_path   = var.vault_license_path
  vault_license        = var.vault_license
  k8s_namespace        = var.k8s_namespace
  k8s_service_account  = var.k8s_service_account
  k8s_config_context   = var.k8s_config_context
  k8s_config_path      = var.k8s_config_path
  vault_image_repo_ent = var.vault_image_repo_ent
  vault_image_tag_ent  = var.vault_image_tag_ent
  vault_chart_version  = var.vault_chart_version
}

