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

variable "postgres_secret_name" {
  default = "postgres-postgresql"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

variable "k8s_db_secret_count" {
  default = 50
}

variable "db_role" {
  default = "dev-postgres"
}

variable "vault_address" {}
variable "vault_token" {}

variable "with_hcp_vault_secrets" {
  default = false
}

variable "hcp_organization_id" {
  type    = string
  default = ""
}

variable "hcp_project_id" {
  type    = string
  default = ""
}

variable "hcp_client_id" {
  type    = string
  default = ""
}

variable "hcp_client_key" {
  type    = string
  default = ""
}

variable "hcp_hvs_app_name" {
  type    = string
  default = "vso"
}
