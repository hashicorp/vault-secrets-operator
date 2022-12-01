terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
    }
    vault = {
      source = "hashicorp/vault"
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

resource "vault_mount" "kvv2" {
  path        = var.vault_kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}
