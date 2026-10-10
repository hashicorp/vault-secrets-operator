# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# kubernetes auth config (kind/EKS only)
resource "vault_auth_backend" "default" {
  count = var.use_hvd ? 0 : 1
  path  = "operator"
  type  = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "operator" {
  count                  = var.use_hvd ? 0 : 1
  namespace              = vault_auth_backend.default[0].namespace
  backend                = vault_auth_backend.default[0].path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}

# approle auth config (HVD only)
resource "random_string" "approle_suffix" {
  count   = var.use_hvd ? 1 : 0
  length  = 4
  special = false
  upper   = false
}

resource "vault_auth_backend" "approle" {
  count = var.use_hvd ? 1 : 0
  path  = "operator-approle-${random_string.approle_suffix[0].result}"
  type  = "approle"
}

resource "vault_approle_auth_backend_role" "operator" {
  count          = var.use_hvd ? 1 : 0
  backend        = vault_auth_backend.approle[0].path
  role_name      = local.auth_role_operator
  token_policies = [vault_policy.operator.name]
  token_period   = 120
}

resource "vault_approle_auth_backend_role_secret_id" "operator" {
  count     = var.use_hvd ? 1 : 0
  backend   = vault_auth_backend.approle[0].path
  role_name = vault_approle_auth_backend_role.operator[0].role_name
}

resource "kubernetes_secret" "operator_approle_secretid" {
  count = var.use_hvd ? 1 : 0
  metadata {
    name      = "operator-approle-secretid"
    namespace = local.operator_namespace
  }
  data = {
    id = vault_approle_auth_backend_role_secret_id.operator[0].secret_id
  }
}

resource "vault_policy" "revocation" {
  name   = "operator-revocation"
  policy = <<EOT
path "sys/leases/revoke" {
  capabilities = ["update"]
}
EOT
}


resource "kubernetes_manifest" "vault-connection-default" {
  count = !var.deploy_operator_via_helm ? 1 : 0
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultConnection"
    metadata = {
      name      = "default"
      namespace = local.operator_namespace
    }
    spec = {
      address = var.k8s_vault_connection_address
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

module "vso-helm" {
  count                        = var.deploy_operator_via_helm ? 1 : 0
  source                       = "../vso-helm"
  create_namespace             = var.create_namespace
  operator_namespace           = var.operator_namespace
  operator_image_repo          = var.operator_image_repo
  operator_image_tag           = var.operator_image_tag
  enable_default_connection    = var.enable_default_connection
  enable_default_auth_method   = false
  operator_helm_chart_path     = var.operator_helm_chart_path
  k8s_vault_connection_address = var.k8s_vault_connection_address
  client_cache_config = {
    persistence_model                = "direct-encrypted"
    revoke_client_cache_on_uninstall = false
    storage_encryption = {
      enabled                         = true
      vault_connection_ref            = ""
      namespace                       = ""
      method                          = var.use_hvd ? vault_auth_backend.approle[0].type : vault_auth_backend.default[0].type
      mount                           = var.use_hvd ? vault_auth_backend.approle[0].path : vault_auth_backend.default[0].path
      transit_mount                   = vault_transit_secret_cache_config.cache.backend
      key_name                        = vault_transit_secret_backend_key.cache.name
      kubernetes_auth_role            = var.use_hvd ? "" : vault_kubernetes_auth_backend_role.operator[0].role_name
      kubernetes_auth_service_account = var.use_hvd ? "" : local.operator_service_account_name
      kubernetes_auth_token_audiences = var.use_hvd ? "" : "{${vault_kubernetes_auth_backend_role.operator[0].audience}}"
    }
  }
  manager_extra_args = [
    "-zap-log-level=6"
  ]
}
