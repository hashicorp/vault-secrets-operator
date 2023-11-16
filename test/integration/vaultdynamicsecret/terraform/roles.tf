# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "kubernetes_cluster_role" "k8s_secrets" {
  metadata {
    name = "${local.name_prefix}-k8s-secrets"
  }
  rule {
    api_groups = [""]
    resources  = ["serviceaccounts/token"]
    verbs      = ["create"]
  }
}

resource "kubernetes_cluster_role_binding" "k8s_secrets" {
  metadata {
    name = "${local.name_prefix}-k8s-secrets"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.k8s_secrets.metadata[0].name
  }
  subject {
    kind      = "ServiceAccount"
    namespace = var.k8s_vault_namespace
    name      = var.k8s_vault_service_account
  }
}

resource "vault_kubernetes_secret_backend" "k8s_secrets" {
  namespace            = local.namespace
  path                 = "${local.name_prefix}-k8s"
  kubernetes_host      = var.k8s_host
  disable_local_ca_jwt = false
}

resource "vault_kubernetes_secret_backend_role" "k8s_secrets" {
  name                          = local.k8s_secret_role
  namespace                     = vault_kubernetes_secret_backend.k8s_secrets.namespace
  backend                       = vault_kubernetes_secret_backend.k8s_secrets.path
  allowed_kubernetes_namespaces = ["*"]
  token_max_ttl                 = 600
  token_default_ttl             = 600
  service_account_name          = "default"
}

resource "vault_policy" "k8s_secrets" {
  namespace = vault_kubernetes_secret_backend.k8s_secrets.namespace
  name      = "${local.auth_policy}-k8s-secrets"
  policy    = <<EOT
path "${vault_kubernetes_secret_backend.k8s_secrets.path}/creds/${vault_kubernetes_secret_backend_role.k8s_secrets.name}" {
  capabilities = ["read", "update"]
}
EOT
}
