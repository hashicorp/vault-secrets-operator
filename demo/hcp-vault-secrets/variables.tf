# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "name_prefix" {
  type    = string
  default = "vault-secrets-demo"
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
  default = true
}

variable "chart" {
  default = "vault-secrets-operator"
}

variable "vault_secret_app_name" {}
