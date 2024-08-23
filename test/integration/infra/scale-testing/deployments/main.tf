# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

module "vso-helm" {
  source                       = "../../../../modules/vso-helm"
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = false
  enable_default_auth_method   = false
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address

  manager_extra_args = [
    "-min-refresh-after-hvsa=3s",
    "-zap-log-level=6"
  ]
}

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
