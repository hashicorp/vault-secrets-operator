# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

resource "kubernetes_manifest" "hcp-vsa-auth-default" {
  count = var.with_hcp_vault_secrets ? 1 : 0
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "HCPAuth"
    metadata = {
      name      = "default"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      method         = "servicePrincipal"
      organizationID = var.hcp_organization_id
      projectID      = var.hcp_project_id
      servicePrincipal = {
        secretRef = kubernetes_secret.hcp-vsa-sp[0].metadata[0].name
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }

  depends_on = [module.vso-helm]
}

resource "kubernetes_secret" "hcp-vsa-sp" {
  count = var.with_hcp_vault_secrets ? 1 : 0
  metadata {
    name      = "vso-db-demo-hcp-vsa-sp"
    namespace = local.k8s_namespace
  }
  data = {
    "clientID"     = var.hcp_client_id
    "clientSecret" = var.hcp_client_secret
  }
}

resource "kubernetes_manifest" "hcp-vsa-secret" {
  count = var.with_hcp_vault_secrets ? 1 : 0
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "HCPVaultSecretsApp"
    metadata = {
      name      = "vso-db-demo-hcp-vsa"
      namespace = local.k8s_namespace
    }
    spec = {
      appName      = var.hcp_hvs_app_name
      refreshAfter = "5s"
      destination = {
        create = true
        name   = "vso-db-demo-hcp-vsa"
      }
    }
  }
}
