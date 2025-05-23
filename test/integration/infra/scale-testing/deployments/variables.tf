# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "cluster_name" {
  description = "Name of the EKS cluster"
  type        = string
}

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

variable "vault_image_repo_ent" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault-enterprise"
}

variable "vault_image_tag_ent" {
  default = "1.17-ent"
}

variable "vault_enterprise" {
  type    = bool
  default = true
}

variable "vault_chart_version" {
  default = "0.29.1"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}
