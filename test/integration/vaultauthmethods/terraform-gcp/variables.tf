# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

variable "test_id" {
  default = ""
}

variable "k8s_vault_connection_address" {}

variable "k8s_config_context" {
  default = "kind-kind"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_test_namespace" {
  default = "testing"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

variable "vault_test_namespace" {
  default = "tenant-1"
}

variable "vault_policy" {
  default = "dev"
}

variable "auth_role" {
  default = "role1"
}

variable "run_gcp_tests" {
  type    = bool
  default = false
}

variable "gcp_project_id" {
  type    = string
  default = ""
}

variable "gcp_region" {
  type    = string
  default = "us-west1"
}
