# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "k8s_test_namespace" {
  default = "testing"
}

variable "test_service_account" {
  default = ""
}

variable "k8s_vault_connection_address" {}

variable "k8s_config_context" {
  default = "kind-kind"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_host" {
  default = "https://kubernetes.default.svc"
}

variable "k8s_ca_pem" {
  default = ""
}

variable "k8s_token" {
  default = ""
}

variable "vault_oidc_discovery_url" {
  default = "https://kubernetes.default.svc.cluster.local"
}

variable "vault_oidc_ca" {
  default = true
}

variable "vault_kvv2_mount_path" {
  default = "kvv2"
}

variable "vault_test_namespace" {
  default = "tenant-1"
}

# AppRole specific variables
variable "approle_role_name" {
  type    = string
  default = "approle"
}

variable "approle_mount_path" {
  type    = string
  default = "approle"
}

variable "vault_enterprise" {
  type    = bool
  default = false
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

variable "auth_role" {
  default = "role1"
}
