# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# demonstrates how to setup cross Vault namespace for VSO and K8s auth when var.vault_enterprise = true

# sets the group policy application to work with with cross Vault namespace auth
resource "vault_generic_endpoint" "sys-group-policy-application" {
  count = var.vault_enterprise ? 1 : 0
  data_json = jsonencode(
    {
      group_policy_application_mode = "any"
    }
  )
  path = "sys/config/group-policy-application"
}

# default service account from the tenant namespace
resource "kubernetes_service_account" "tenant" {
  metadata {
    namespace = local.k8s_namespace_name
    name      = "tenant"
    labels = {
      "x-ns" : var.vault_enterprise
    }
  }
}

# identity entity that maps to the service account name
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_name"
resource "vault_identity_entity" "tenant-sa-name" {
  namespace = local.namespace
  name      = "${kubernetes_service_account.tenant.metadata[0].namespace}/${kubernetes_service_account.tenant.metadata[0].name}"
}

# identity entity that maps to the service account UID
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_uid"
resource "vault_identity_entity" "tenant-sa-uid" {
  namespace = local.namespace
  name      = kubernetes_service_account.tenant.metadata[0].uid
}

# identity entity alias that maps to the service account UID
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_uid"
resource "vault_identity_entity_alias" "tenant-sa-uid" {
  namespace      = local.namespace
  name           = kubernetes_service_account.tenant.metadata[0].uid
  mount_accessor = vault_auth_backend.default.accessor
  canonical_id   = vault_identity_entity.tenant-sa-uid.id
}

# identity entity alias that maps to the service account name
# provides cross Vault namespace when the k8s auth role's alias_name_source = "serviceaccount_name"
resource "vault_identity_entity_alias" "tenant-sa-name" {
  namespace      = local.namespace
  name           = vault_identity_entity.tenant-sa-name.name
  mount_accessor = vault_auth_backend.default.accessor
  canonical_id   = vault_identity_entity.tenant-sa-name.id
}

# parent identity group that holds all vso tenant entities
resource "vault_identity_group" "vso-tenants-parent" {
  namespace = local.namespace
  name      = "vso-tenants-parent"
  type      = "internal"
  member_entity_ids = [
    vault_identity_entity_alias.tenant-sa-name.canonical_id,
    vault_identity_entity_alias.tenant-sa-uid.canonical_id,
  ]
}

# identity group that provides cross namespace support when var.vault_enterprise is true
resource "vault_identity_group" "vso-tenants" {
  namespace        = local.tenant_namespace
  member_group_ids = [vault_identity_group.vso-tenants-parent.id]
  name             = "vso-tenants"
  policies = [
    vault_policy.tenant-kv.name,
  ]
  type = "internal"
}

resource "vault_policy" "tenant-kv" {
  name      = "tenant-kv"
  namespace = local.tenant_namespace
  policy    = <<EOF
path "${vault_mount.tenant-kv.path}/data/${vault_kv_secret_v2.tenant-kv.name}" {
   capabilities = ["read"]
}
EOF
}

resource "vault_mount" "tenant-kv" {
  namespace = local.tenant_namespace
  path      = "tenant-kv"
  type      = "kv-v2"
}

resource "vault_kv_secret_v2" "tenant-kv" {
  namespace           = local.tenant_namespace
  mount               = vault_mount.tenant-kv.path
  name                = "x-ns"
  delete_all_versions = true
  data_json = jsonencode(
    {
      x_ns   = "true"
      secret = "foo"
    }
  )
}

# tenant role used to test cross vault namespace with identity alias using the serviceaccount name
resource "vault_kubernetes_auth_backend_role" "tenant-sa-name" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = "${local.auth_role}-alias"
  alias_name_source                = "serviceaccount_name"
  bound_service_account_names      = [kubernetes_service_account.tenant.metadata[0].name]
  bound_service_account_namespaces = [kubernetes_service_account.tenant.metadata[0].namespace]
  token_period                     = 120
  token_policies = [
    vault_policy.db.name,
  ]
  audience = "vault"
}

# tenant role used to test cross vault namespace with identity alias using the serviceaccount UID
resource "vault_kubernetes_auth_backend_role" "tenant-sa-uid" {
  namespace                        = vault_auth_backend.default.namespace
  backend                          = vault_kubernetes_auth_backend_config.default.backend
  role_name                        = "${local.auth_role}-uid"
  alias_name_source                = "serviceaccount_uid"
  bound_service_account_names      = [kubernetes_service_account.tenant.metadata[0].name]
  bound_service_account_namespaces = [kubernetes_service_account.tenant.metadata[0].namespace]
  token_period                     = 120
  token_policies = [
    vault_policy.db.name,
  ]
  audience = "vault"
}

resource "kubernetes_manifest" "tenant-vault-auth-global" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuthGlobal"
    metadata = {
      name      = "vso-auth-global"
      namespace = local.k8s_namespace
      labels = {
        "x-ns" : var.vault_enterprise
      }
    }
    spec = {
      defaultAuthMethod = "kubernetes"
      kubernetes = {
        namespace      = vault_auth_backend.default.namespace
        mount          = vault_auth_backend.default.path
        serviceAccount = kubernetes_service_account.tenant.metadata[0].name
        audiences = [
          "vault"
        ]
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

# VaultAuth for service account UID K8s auth role
resource "kubernetes_manifest" "tenant-vault-auth-sa-uid" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "vso-auth-sa-uid"
      namespace = local.k8s_namespace
      labels = {
        "x-ns" : var.vault_enterprise
      }
    }
    spec = {
      vaultAuthGlobalRef = kubernetes_manifest.tenant-vault-auth-global.manifest.metadata.name
      kubernetes = {
        role = vault_kubernetes_auth_backend_role.tenant-sa-uid.role_name
      }
    }
  }
  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

# VaultAuth for service account name K8s auth role
resource "kubernetes_manifest" "tenant-vault-auth-sa-name" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultAuth"
    metadata = {
      name      = "vso-auth-sa-name"
      namespace = local.k8s_namespace
      labels = {
        "x-ns" : var.vault_enterprise
      }
    }
    spec = {
      vaultAuthGlobalRef = kubernetes_manifest.tenant-vault-auth-global.manifest.metadata.name
      kubernetes = {
        role = vault_kubernetes_auth_backend_role.tenant-sa-name.role_name
      }
    }
  }
  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

resource "kubernetes_manifest" "tenant-vss-uid" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultStaticSecret"
    metadata = {
      name      = "vso-${local.name_prefix}-vss-uid"
      namespace = local.k8s_namespace
      labels = {
        "x-ns" : var.vault_enterprise
      }
    }
    spec = {
      namespace      = local.tenant_namespace
      mount          = vault_mount.tenant-kv.path
      type           = "kv-v2"
      path           = vault_kv_secret_v2.tenant-kv.name
      vaultAuthRef   = kubernetes_manifest.tenant-vault-auth-sa-uid.manifest.metadata.name
      hmacSecretData = true
      destination = {
        create = true
        name   = "vso-${local.name_prefix}-vss-uid"
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

resource "kubernetes_manifest" "tenant-vss-name" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultStaticSecret"
    metadata = {
      name      = "vso-${local.name_prefix}-vss-name"
      namespace = local.k8s_namespace
      labels = {
        "x-ns" : var.vault_enterprise
      }
    }
    spec = {
      namespace      = local.tenant_namespace
      mount          = vault_mount.tenant-kv.path
      type           = "kv-v2"
      path           = vault_kv_secret_v2.tenant-kv.name
      vaultAuthRef   = kubernetes_manifest.tenant-vault-auth-sa-name.manifest.metadata.name
      hmacSecretData = true
      destination = {
        create = true
        name   = "vso-${local.name_prefix}-vss-name"
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}
