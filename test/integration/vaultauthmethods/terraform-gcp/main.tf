# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.2.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "5.28.0"
    }
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

provider "google" {
  project = var.gcp_project_id
  region  = var.gcp_region
}

provider "vault" {
}

# gcp auth config
module "gke-workload-identity" {
  count      = var.run_gcp_tests ? 1 : 0
  source     = "terraform-google-modules/kubernetes-engine/google//modules/workload-identity"
  version    = "30.2.0"
  name       = "workload-identity-sa-${var.test_id}"
  namespace  = var.k8s_test_namespace
  project_id = var.gcp_project_id
  roles      = ["roles/container.viewer"]
}

resource "vault_gcp_auth_backend" "gcp" {
  count       = var.run_gcp_tests ? 1 : 0
  credentials = base64decode(one(google_service_account_key.vault-key).private_key)
  path        = "gcp"
  namespace   = local.namespace
}

resource "vault_gcp_auth_backend_role" "role" {
  count     = var.run_gcp_tests ? 1 : 0
  backend   = one(vault_gcp_auth_backend.gcp).path
  namespace = local.namespace
  role      = "${var.auth_role}-gcp"
  type      = "iam"
  bound_service_accounts = [
    one(module.gke-workload-identity).gcp_service_account_email,
  ]
  token_policies = [var.vault_policy]

  # The generateIdToken API always returns jwt's with a ttl of 1h, and the vault
  # default is 15m
  max_jwt_exp = 3600
}

# Create a new Service account for Vault's gcp auth method
resource "google_service_account" "vault" {
  count        = var.run_gcp_tests ? 1 : 0
  account_id   = "sa-vault-${var.test_id}"
  display_name = "GKE Service Account for Vault auth"
  project      = var.gcp_project_id
}

resource "google_project_iam_member" "vault-auth-iam" {
  count   = var.run_gcp_tests ? 1 : 0
  project = var.gcp_project_id
  role    = "roles/iam.serviceAccountKeyAdmin"
  member  = "serviceAccount:${one(google_service_account.vault).email}"
}

resource "google_service_account_key" "vault-key" {
  count              = var.run_gcp_tests ? 1 : 0
  service_account_id = one(google_service_account.vault).name
}
