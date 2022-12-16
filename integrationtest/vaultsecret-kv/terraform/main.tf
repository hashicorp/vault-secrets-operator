# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.16"
    }
    vault = {
      source = "hashicorp/vault"
      version = "~> 3.11"
    }
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

resource "kubernetes_namespace" "tenant-1" {
  metadata {
    name = var.k8s_test_namespace
  }
}

resource "kubernetes_secret" "secret1" {
    metadata {
      name = "secret1"
      namespace = var.k8s_test_namespace
    }
}

provider "vault" {
  # Configuration options
}

resource "vault_mount" "kvv2-ent" {
  count = var.vault_enterprise ? 1 : 0
  namespace = vault_namespace.test[count.index].path
  path        = var.vault_kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_mount" "kvv2" {
  count = var.vault_enterprise == "false" ? 1 : 0
  path        = var.vault_kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_namespace" "test" {
  count = var.vault_enterprise ? 1 : 0
  path = var.vault_test_namespace
}
