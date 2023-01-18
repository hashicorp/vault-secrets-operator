# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.16"
    }
    vault = {
      source  = "hashicorp/vault"
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

resource "kubernetes_secret" "pki1" {
  metadata {
    name      = "pki1"
    namespace = var.k8s_test_namespace
  }
}

provider "vault" {
  # Configuration options
}

// Vault OSS setup
resource "vault_mount" "pki" {
  count                     = var.vault_enterprise ? 0 : 1
  path                      = var.vault_pki_mount_path
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role" {
  count            = var.vault_enterprise ? 0 : 1
  backend          = vault_mount.pki[count.index].path
  name             = "secret"
  ttl              = 3600
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com"]
  allow_subdomains = true
}

resource "vault_pki_secret_backend_root_cert" "test" {
  count                = var.vault_enterprise ? 0 : 1
  backend              = vault_mount.pki[count.index].path
  type                 = "internal"
  common_name          = "Root CA"
  ttl                  = "315360000"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "My OU"
  organization         = "My organization"
}

// Vault Enterprise setup
resource "vault_namespace" "test" {
  count = var.vault_enterprise ? 1 : 0
  path  = var.vault_test_namespace
}

resource "vault_mount" "pki-ent" {
  count                     = var.vault_enterprise ? 1 : 0
  namespace                 = vault_namespace.test[count.index].path
  path                      = var.vault_pki_mount_path
  type                      = "pki"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

resource "vault_pki_secret_backend_role" "role-ent" {
  count            = var.vault_enterprise ? 1 : 0
  namespace        = vault_namespace.test[count.index].path
  backend          = vault_mount.pki-ent[count.index].path
  name             = "secret"
  ttl              = 3600
  allow_ip_sans    = true
  key_type         = "rsa"
  key_bits         = 4096
  allowed_domains  = ["example.com"]
  allow_subdomains = true
}

resource "vault_pki_secret_backend_root_cert" "test-ent" {
  count                = var.vault_enterprise ? 1 : 0
  namespace            = vault_namespace.test[count.index].path
  backend              = vault_mount.pki-ent[count.index].path
  type                 = "internal"
  common_name          = "Root CA"
  ttl                  = "315360000"
  format               = "pem"
  private_key_format   = "der"
  key_type             = "rsa"
  key_bits             = 4096
  exclude_cn_from_sans = true
  ou                   = "My OU"
  organization         = "My organization"
}
