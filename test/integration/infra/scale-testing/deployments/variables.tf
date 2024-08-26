# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  default = "../../../../../../chart"
}

variable "enable_default_connection" {
  type    = bool
  default = true
}

variable "enable_default_auth_method" {
  type    = bool
  default = true
}

variable "k8s_vault_connection_address" {
  default = ""
}

variable "k8s_auth_default_mount" {
  default = ""
}

variable "vault_test_namespace" {
  default = ""
}

variable "operator_allowednamespaces" {
  type    = list(string)
  default = []
}

variable "k8s_auth_default_role" {
  default = ""
}

variable "k8s_auth_default_token_audiences" {
  type    = list(string)
  default = []
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.8.1"
}

variable "cpu_limits" {
  default = ""
}

variable "memory_limits" {
  default = ""
}

variable "cpu_requests" {
  default = ""
}

variable "memory_requests" {
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

variable "vault_license_path" {
  default = ""
}

variable "vault_license" {
  default = ""
}

variable "k8s_namespace" {
  default = "vault"
}

variable "k8s_service_account" {
  default = "vault"
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "vault_image_repo" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault"
}

variable "vault_image_repo_ent" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault-enterprise"
}

variable "vault_image_tag" {
  default = "1.17"
}

variable "vault_image_tag_ent" {
  default = "1.17-ent"
}

variable "vault_enterprise" {
  type    = bool
  default = true
}

variable "vault_chart_version" {
  default = "0.28.1"
}

variable "install_kube_prometheus" {
  type    = bool
  default = false
}

variable "metrics_server_enabled" {
  type    = bool
  default = true
}

