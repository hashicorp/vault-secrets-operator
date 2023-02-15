# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "k8s_test_namespace" {
  default = "testing"
}

variable "k8s_vault_namespace" {
  default = "demo"
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

variable "vault_pki_mount_path" {
  default = "pki"
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
  default = "false"
}

variable "vault_connection_name" {
  default = "test"
}

variable "vault_authmethod_name" {
  default = "test"
}

variable "vault_authmethod_role" {
  default = "test"
}

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}
