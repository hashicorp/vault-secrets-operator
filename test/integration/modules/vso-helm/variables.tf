# Copyright (c) HashiCorp, Inck
# SPDX-License-Identifier: BUSL-1.1
variable "k8s_vault_connection_address" {
  default = ""
}

variable "name" {
  default = "vault-secrets-operator"
}

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}

variable "k8s_auth_default_token_audiences" {
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

variable "repository" {
  default = "https://helm.releases.hashicorp.com"
}

variable "chart" {
  default = "../../../../chart"
}

variable "chart_version" {
  default = ""
}
