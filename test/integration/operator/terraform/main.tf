# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "2.13.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.2.0"
    }
  }
}

provider "vault" {
  # Configuration options
  address = var.vault_address
  token   = var.vault_token
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

# kubernetes auth config
resource "vault_auth_backend" "default" {
  path = "operator"
  type = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "operator" {
  namespace              = vault_auth_backend.default.namespace
  backend                = vault_auth_backend.default.path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
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
  source                       = "../../modules/vso-helm"
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
    "-min-refresh-after-hvsa=3s",
    "-zap-log-level=6"
  ]
}
