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
    helm = {
      source  = "hashicorp/helm"
      version = "2.13.1"
    }
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

resource "kubernetes_namespace" "tenant-1" {
  metadata {
    name = var.k8s_test_namespace
  }
}

resource "kubernetes_default_service_account" "default" {
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
}

resource "kubernetes_secret" "default" {
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    name      = "test-sa-secret"
    annotations = {
      "kubernetes.io/service-account.name" = kubernetes_default_service_account.default.metadata[0].name
    }
  }
  type                           = "kubernetes.io/service-account-token"
  wait_for_service_account_token = true
}

provider "vault" {
  # Configuration options
}

resource "vault_mount" "kvv2" {
  namespace   = local.namespace
  path        = var.vault_kvv2_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "KV Version 2 secret engine mount"
}

resource "vault_policy" "default" {
  name      = "dev"
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.kvv2.path}/*" {
  capabilities = ["read"]
}
EOT
}

resource "vault_namespace" "test" {
  count = var.vault_enterprise ? 1 : 0
  path  = var.vault_test_namespace
}

resource "vault_auth_backend" "default" {
  namespace = local.namespace
  type      = "kubernetes"
}

resource "vault_kubernetes_auth_backend_config" "default" {
  namespace              = vault_auth_backend.default.namespace
  backend                = vault_auth_backend.default.path
  kubernetes_host        = var.k8s_host
  disable_iss_validation = true
}

resource "vault_kubernetes_auth_backend_role" "default" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = var.auth_role
  bound_service_account_names      = [kubernetes_default_service_account.default.metadata[0].name]
  bound_service_account_namespaces = [kubernetes_namespace.tenant-1.metadata[0].name]
  token_ttl                        = 3600
  token_policies                   = [vault_policy.default.name]
  audience                         = "vault"
}

# jwt auth config
resource "vault_jwt_auth_backend" "dev" {
  namespace             = local.namespace
  path                  = "jwt"
  oidc_discovery_url    = var.vault_oidc_discovery_url
  oidc_discovery_ca_pem = var.vault_oidc_ca ? nonsensitive(kubernetes_secret.default.data["ca.crt"]) : ""
}

resource "vault_jwt_auth_backend_role" "dev" {
  namespace       = vault_jwt_auth_backend.dev.namespace
  backend         = "jwt"
  role_name       = var.auth_role
  role_type       = "jwt"
  bound_audiences = ["vault"]
  user_claim      = "sub"
  token_policies  = [vault_policy.default.name]
}

# Create the Vault Auth Backend for AppRole
resource "vault_auth_backend" "approle" {
  namespace = local.namespace
  type      = "approle"
  path      = var.approle_mount_path
}

# Create the Vault Auth Backend Role for AppRole
resource "vault_approle_auth_backend_role" "role" {
  namespace = local.namespace
  backend   = vault_auth_backend.approle.path
  role_name = var.approle_role_name
  # role_id is auto-generated, and we use this to do the Login
  token_policies = [vault_policy.approle.name]
}

# Creates the Secret ID for the AppRole
resource "vault_approle_auth_backend_role_secret_id" "id" {
  namespace = local.namespace
  backend   = vault_auth_backend.approle.path
  role_name = vault_approle_auth_backend_role.role.role_name
}

# Kubernetes secret to hold the secretid
resource "kubernetes_secret" "secretid" {
  metadata {
    name      = "secretid"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
  }
  data = {
    id = vault_approle_auth_backend_role_secret_id.id.secret_id
  }
}

resource "vault_policy" "approle" {
  name      = "approle"
  namespace = local.namespace
  policy    = <<EOT
path "${vault_mount.kvv2.path}/*" {
  capabilities = ["read","list","update"]
}
path "auth/${vault_auth_backend.approle.path}/login" {
  capabilities = ["read","update"]
}
EOT
}

# aws auth config
resource "kubernetes_service_account" "irsa_assumable" {
  count = var.run_aws_tests ? 1 : 0
  metadata {
    name      = "irsa-test"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    annotations = {
      "eks.amazonaws.com/role-arn" : var.irsa_assumable_role_arn,
    }
  }
}

resource "vault_auth_backend" "aws" {
  count     = var.run_aws_tests ? 1 : 0
  namespace = local.namespace
  type      = "aws"
  path      = "aws"
}

resource "vault_aws_auth_backend_client" "aws" {
  count        = var.run_aws_tests ? 1 : 0
  namespace    = local.namespace
  backend      = one(vault_auth_backend.aws).path
  sts_region   = var.aws_region
  sts_endpoint = "https://sts.${var.aws_region}.amazonaws.com"
}

resource "vault_aws_auth_backend_role" "aws-irsa" {
  count                    = var.run_aws_tests ? 1 : 0
  namespace                = local.namespace
  backend                  = one(vault_auth_backend.aws).path
  role                     = "${var.auth_role}-aws-irsa"
  auth_type                = "iam"
  bound_iam_principal_arns = [var.irsa_assumable_role_arn]
  token_policies           = [vault_policy.default.name]
}

resource "vault_aws_auth_backend_role" "aws-node" {
  count                    = var.run_aws_tests ? 1 : 0
  namespace                = local.namespace
  backend                  = one(vault_auth_backend.aws).path
  role                     = "${var.auth_role}-aws-node"
  auth_type                = "iam"
  bound_iam_principal_arns = ["arn:aws:iam::${var.aws_account_id}:role/eks-nodes-eks-*"]
  token_policies           = [vault_policy.default.name]
}

resource "vault_aws_auth_backend_role" "aws-instance-profile" {
  count                           = var.run_aws_tests ? 1 : 0
  namespace                       = local.namespace
  backend                         = one(vault_auth_backend.aws).path
  role                            = "${var.auth_role}-aws-instance-profile"
  auth_type                       = "iam"
  inferred_entity_type            = "ec2_instance"
  inferred_aws_region             = var.aws_region
  bound_account_ids               = [var.aws_account_id]
  bound_iam_instance_profile_arns = ["arn:aws:iam::${var.aws_account_id}:instance-profile/eks-*"]
  token_policies                  = [vault_policy.default.name]
}

resource "vault_aws_auth_backend_role" "aws-static" {
  count                    = var.run_aws_static_creds_test ? 1 : 0
  namespace                = local.namespace
  backend                  = one(vault_auth_backend.aws).path
  role                     = "${var.auth_role}-aws-static"
  auth_type                = "iam"
  bound_iam_principal_arns = [var.aws_static_creds_role]
  token_policies           = [vault_policy.default.name]
}

resource "kubernetes_secret" "static-creds" {
  count = var.run_aws_static_creds_test ? 1 : 0
  metadata {
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    name      = "aws-static-creds"
  }
  data = {
    "access_key_id"     = var.test_aws_access_key_id
    "secret_access_key" = var.test_aws_secret_access_key
    "session_token"     = var.test_aws_session_token
  }
}
