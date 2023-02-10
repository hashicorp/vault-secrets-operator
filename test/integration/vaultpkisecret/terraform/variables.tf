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
