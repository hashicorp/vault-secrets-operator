# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "vault_license_path" {
  default = ""
}

variable "vault_license" {
  default = ""
}

variable "k8s_namespace" {
  default = "demo"
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
  default = "1.12"
}

variable "vault_image_tag_ent" {
  default = "1.12-ent"
}

variable "vault_enterprise" {
  type    = bool
  default = true
}

variable "vault_chart_version" {
  default = "0.23.0"
}
