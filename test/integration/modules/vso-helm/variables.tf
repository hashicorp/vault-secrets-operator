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

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}

variable "k8s_auth_default_token_audiences" {
  default = ""
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
