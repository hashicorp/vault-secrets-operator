# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "k8s_test_namespace" {
  default = "testing"
}


variable "k8s_config_context" {
  default = "kind-kind"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_host" {
  default = "https://kubernetes.default.svc"
}

variable "vault_kv_mount_path" {
  default = "kv"
}

variable "vault_kvv2_mount_path" {
  default = "kvv2"
}

variable "vault_test_namespace" {
  default = "tenant-1"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  default = "../../../../chart"
}

variable "deploy_operator_via_helm" {
  type    = bool
  default = false
}

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
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
