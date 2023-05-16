# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

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
