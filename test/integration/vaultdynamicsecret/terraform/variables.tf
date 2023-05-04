# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "operator_namespace_name" {
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

variable "vault_token_period" {
  default = 30
}

variable "vault_db_default_lease_ttl" {
  default = 60
}

variable "vault_address" {}
variable "vault_token" {}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  default = "../../../../chart"
}

variable "deploy_operator_via_helm" {
  type    = bool
  default = false
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}
