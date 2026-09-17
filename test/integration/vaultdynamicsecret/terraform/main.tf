# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = "2.16.1"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.30.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "4.2.0"
    }
    # aws + tls are only used when use_hvd=true, to provision an EC2 instance
    # that hosts Postgres for HVD (which cannot reach in-cluster Postgres).
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    # http is only used when use_hvd=true and ssh_ingress_cidr is left empty,
    # to auto-detect the test runner's current public IP.
    http = {
      source  = "hashicorp/http"
      version = "~> 3.4"
    }
  }
}

provider "vault" {
  # address and token are picked up from VAULT_ADDR/VAULT_TOKEN env vars set
  # by the test runner before invoking go test (var.vault_address/vault_token
  # are effectively unused today — kept only for potential explicit overrides).
  # Do NOT set namespace here — the vault provider concatenates the provider
  # block namespace with the VAULT_NAMESPACE env var (also set by the test
  # runner for HVD), producing "admin/admin". Namespacing for HVD is instead
  # handled per-resource via local.namespace (see locals.tf), which resolves
  # to null under HVD so resources rely on the env-var-derived root context.
  address = var.vault_address
  token   = var.vault_token
}

provider "aws" {
  # Terraform provider blocks can't be count-guarded, so this provider is
  # always configured even under kind (use_hvd=false), where no aws_* resource
  # is ever actually created (all are count-guarded to use_hvd ? 1 : 0) and no
  # real AWS credentials are available (e.g. in the standard kind-only CI
  # matrix). Without the overrides below, Configure() fails outright with
  # "No valid credential sources found" before Terraform ever evaluates any
  # resource's count. Static dummy credentials + skipping all validation lets
  # the provider configure as a no-op under kind; it's never used to make a
  # real AWS API call in that mode. Under HVD, real credentials/validation
  # behavior are fully preserved (all overrides become no-ops/false).
  region                      = local.aws_region
  access_key                  = var.use_hvd ? null : "test"
  secret_key                  = var.use_hvd ? null : "test"
  skip_credentials_validation = !var.use_hvd
  skip_requesting_account_id  = !var.use_hvd
  skip_metadata_api_check     = !var.use_hvd
  skip_region_validation      = !var.use_hvd
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

resource "kubernetes_namespace" "dev" {
  metadata {
    name = local.k8s_namespace
  }
}

resource "random_string" "prefix" {
  length  = 10
  upper   = false
  special = false
  keepers = {
    name_prefix = var.name_prefix
  }
}

resource "vault_namespace" "test" {
  count = (var.vault_enterprise && !var.use_hvd) ? 1 : 0
  path  = "${local.name_prefix}-ns"
}

# kubernetes auth config (kind/EKS only — HVD cannot reach the kind cluster's
# private API server to validate service account JWTs)
resource "vault_auth_backend" "default" {
  count     = var.use_hvd ? 0 : 1
  namespace = local.namespace
  path      = local.auth_mount
  type      = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "dev" {
  count                  = var.use_hvd ? 0 : 1
  namespace              = vault_auth_backend.default[0].namespace
  backend                = vault_auth_backend.default[0].path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}
resource "vault_kubernetes_auth_backend_role" "dev" {
  count             = var.use_hvd ? 0 : 1
  namespace         = vault_auth_backend.default[0].namespace
  backend           = vault_kubernetes_auth_backend_config.dev[0].backend
  role_name         = local.auth_role
  alias_name_source = "serviceaccount_name"
  bound_service_account_names = [
    "default",
    # used by some tests that create their own service accounts
    "sa-*",
    # used by xns tests
    "${local.name_prefix}-xns-sa-*"
  ]
  bound_service_account_namespaces = [kubernetes_namespace.dev.metadata[0].name]
  token_period                     = var.vault_token_period
  token_policies                   = local.dev_token_policies
  audience                         = "vault"
}

# ── AppRole auth backend (HVD only) ───────────────────────────────────────
resource "vault_auth_backend" "approle" {
  count     = var.use_hvd ? 1 : 0
  namespace = local.namespace
  path      = "${local.auth_mount}-approle"
  type      = "approle"
}

resource "vault_approle_auth_backend_role" "dev" {
  count          = var.use_hvd ? 1 : 0
  namespace      = local.namespace
  backend        = vault_auth_backend.approle[0].path
  role_name      = local.auth_role
  token_period   = var.vault_token_period
  token_policies = local.dev_token_policies
}

resource "vault_approle_auth_backend_role_secret_id" "dev" {
  count     = var.use_hvd ? 1 : 0
  namespace = local.namespace
  backend   = vault_auth_backend.approle[0].path
  role_name = vault_approle_auth_backend_role.dev[0].role_name
}

# Writes secret_id into a k8s Secret in the dev namespace.
# VSO reads this locally — no outbound call from HVD required.
# The key MUST be named "id" — required by VSO's AppRole credential provider.
resource "kubernetes_secret" "approle_secret_id" {
  count = var.use_hvd ? 1 : 0
  metadata {
    name      = "${local.name_prefix}-approle-secret-id"
    namespace = kubernetes_namespace.dev.metadata[0].name
  }
  data = {
    id = vault_approle_auth_backend_role_secret_id.dev[0].secret_id
  }
}

resource "vault_policy" "revocation" {
  namespace = local.namespace
  name      = "${local.auth_policy}-revocation"
  policy    = <<EOT
path "sys/leases/revoke" {
  capabilities = ["update"]
}
EOT
}
