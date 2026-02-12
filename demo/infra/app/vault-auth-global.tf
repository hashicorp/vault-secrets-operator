# Copyright (c) IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

resource "kubernetes_manifest" "vault-auth-global" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuthGlobal"
    metadata = {
      name      = "default"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      defaultAuthMethod = "kubernetes"
      kubernetes = {
        namespace      = vault_auth_backend.default.namespace
        mount          = vault_auth_backend.default.path
        role           = vault_kubernetes_auth_backend_role.default.role_name
        serviceAccount = "default"
        audiences = [
          "vault",
        ]
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }

  depends_on = [module.vso-helm]
}
