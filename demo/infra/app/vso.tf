# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

module "vso-helm" {
  count                        = var.deploy_operator_via_helm ? 1 : 0
  source                       = "./modules/vso-helm"
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_auth_method   = false
  enable_default_connection    = false
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address
  csi_enabled                  = local.csi_enabled
  csi_logging_level            = "trace"
  create_namespace             = !var.create_namespace
  client_cache_config = {
    persistence_model                = "direct-encrypted"
    revoke_client_cache_on_uninstall = false
    storage_encryption = {
      enabled                         = true
      vault_connection_ref            = ""
      namespace                       = ""
      method                          = vault_auth_backend.default.type
      mount                           = vault_auth_backend.default.path
      transit_mount                   = vault_transit_secret_cache_config.cache.backend
      key_name                        = vault_transit_secret_backend_key.cache.name
      kubernetes_auth_role            = vault_kubernetes_auth_backend_role.operator.role_name
      kubernetes_auth_service_account = local.operator_service_account_name
      kubernetes_auth_token_audiences = "{${vault_kubernetes_auth_backend_role.operator.audience}}"
    }
  }
  manager_extra_args = [
    "-min-refresh-after-hvsa=30s",
    "-zap-log-level=6"
  ]
}
