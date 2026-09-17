# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

provider "vault" {
  # Configuration options
  address   = var.vault_address
  token     = var.vault_token
  namespace = var.vault_namespace # Required for HVD multi-tenancy support
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}
