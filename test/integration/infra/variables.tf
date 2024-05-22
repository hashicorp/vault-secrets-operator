# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "vault_license_path" {
  default = ""
}

variable "vault_license" {
  default = ""
}

variable "k8s_namespace" {
  default = "vault"
}

variable "k8s_service_account" {
  default = "vault"
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "vault_image_repo" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault"
}

variable "vault_image_repo_ent" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault-enterprise"
}

variable "vault_image_tag" {
  default = "1.15"
}

variable "vault_image_tag_ent" {
  default = "1.15-ent"
}

variable "vault_enterprise" {
  type    = bool
  default = true
}

variable "vault_chart_version" {
  default = "0.27.0"
}

variable "install_kube_prometheus" {
  type    = bool
  default = false
}

variable "metrics_server_enabled" {
  type    = bool
  default = true
}
