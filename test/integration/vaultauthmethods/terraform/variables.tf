# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "k8s_test_namespace" {
  type = string
  default = "testing"
}

variable "k8s_vault_connection_address" {
  type = string
}

variable "k8s_config_context" {
  type = string
  default = "kind-kind"
}

variable "k8s_config_path" {
  type = string
  default = "~/.kube/config"
}

variable "k8s_host" {
  type = string
  default = "https://kubernetes.default.svc"
}

variable "vault_kvv2_mount_path" {
  type = string
  default = "kvv2"
}

variable "vault_test_namespace" {
  type = string
  default = "tenant-1"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  type = string
  default = "../../../../chart"
}

variable "operator_namespace" {
  type = string
  default = "vault-secrets-operator-system"
}

# AppRole specific variables
variable "approle_role_name" {
  type = string
  default = "approle"
}
