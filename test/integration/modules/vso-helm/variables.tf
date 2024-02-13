# Copyright (c) HashiCorp, Inck
# SPDX-License-Identifier: BUSL-1.1
variable "k8s_vault_connection_address" {
  default = ""
}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  default = "../../../../chart"
}

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "operator_allowednamespaces" {
  type    = list(string)
  default = []
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}

variable "k8s_auth_default_token_audiences" {
  type    = list(string)
  default = []
}

variable "k8s_auth_default_mount" {
  default = ""
}

variable "k8s_auth_default_role" {
  default = ""
}

variable "enable_default_connection" {
  type    = bool
  default = true
}

variable "enable_default_auth_method" {
  type    = bool
  default = true
}

variable "vault_test_namespace" {
  default = ""
}

variable "client_cache_config" {
  type = object({
    persistence_model                = string
    revoke_client_cache_on_uninstall = bool
    storage_encryption = object({
      enabled                         = bool
      vault_connection_ref            = string
      namespace                       = string
      mount                           = string
      transit_mount                   = string
      key_name                        = string
      method                          = string
      kubernetes_auth_role            = string
      kubernetes_auth_service_account = string
      kubernetes_auth_token_audiences = string
    })
  })

  default = {
    persistence_model                = ""
    revoke_client_cache_on_uninstall = false
    storage_encryption = {
      enabled                         = false
      vault_connection_ref            = ""
      namespace                       = ""
      mount                           = ""
      transit_mount                   = ""
      key_name                        = ""
      method                          = ""
      kubernetes_auth_role            = ""
      kubernetes_auth_service_account = ""
      kubernetes_auth_token_audiences = ""
    }
  }
}

variable "manager_extra_args" {
  type = list(string)
  default = [
    "-zap-log-level=5"
  ]
}
