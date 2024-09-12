# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_host" {
  default = "https://kubernetes.default.svc"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

variable "vault_token_period" {
  default = 30
}

variable "vault_db_default_lease_ttl" {
  default = 60
}

variable "deploy_operator_via_helm" {
  type    = bool
  default = false
}

variable "operator_helm_chart_path" {
  default = "../../../chart"
}

variable "enable_default_connection" {
  type    = bool
  default = false
}

variable "enable_default_auth_method" {
  type    = bool
  default = false
}

variable "k8s_vault_connection_address" {
  default = ""
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}
