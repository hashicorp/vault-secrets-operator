# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "name_prefix" {
  type = string
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "hcp_organization_id" {
  type = string
}

variable "hcp_project_id" {
  type = string
}

variable "hcp_client_id" {
  type      = string
  sensitive = true
}

variable "hcp_client_secret" {
  type      = string
  sensitive = true
}

variable "deploy_operator_via_helm" {
  type    = bool
  default = false
}

variable "operator_helm_chart_path" {
  default = "../../../chart"
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}
