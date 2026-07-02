# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Deploys the CSI app to the Kubernetes cluster. It will pull Vault secrets using the VSO CSI driver.
resource "kubernetes_namespace" "demo-ns-vso-csi" {
  count = local.csi_enabled ? 1 : 0
  metadata {
    name = "demo-ns-vso-csi"
  }
}

resource "kubernetes_service_account" "vso-csi-app" {
  count = local.csi_enabled ? 1 : 0
  metadata {
    name      = "vso-csi-sa"
    namespace = kubernetes_namespace.demo-ns-vso-csi[0].metadata[0].name
  }
}

resource "kubernetes_deployment" "vso-csi-app" {
  count = local.csi_enabled ? 1 : 0
  metadata {
    name      = "vso-csi-app"
    namespace = kubernetes_namespace.demo-ns-vso-csi[0].metadata[0].name
    labels = {
      "app.kubernetes.io/component" = "vso-csi-app"
    }
  }
  spec {
    replicas = 3
    selector {
      match_labels = {
        "app.kubernetes.io/component" = "vso-csi-app"
      }
    }
    template {
      metadata {
        labels = {
          "app.kubernetes.io/component" = "vso-csi-app"
        }
      }
      spec {
        share_process_namespace = true
        affinity {
          node_affinity {
            required_during_scheduling_ignored_during_execution {
              node_selector_term {
                match_expressions {
                  key      = "kubernetes.io/hostname"
                  operator = "In"
                  values = [
                    "vso-demo-worker",
                    "vso-demo-worker2",
                    "vso-demo-worker3",
                  ]
                }
              }
            }
          }
        }
        service_account_name = kubernetes_service_account.vso-csi-app[0].metadata[0].name
        volume {
          name = "vso-csi"
          csi {
            read_only = true
            driver    = "csi.vso.hashicorp.com"
            volume_attributes = {
              csiSecretsNamespace = kubernetes_manifest.csi-secrets[0].manifest.metadata.namespace
              csiSecretsName      = kubernetes_manifest.csi-secrets[0].manifest.metadata.name
            }
          }
        }
        container {
          name              = "app-num-uses-10"
          image             = "hashicorp/vault-secrets-operator-csi-demo-app:latest"
          image_pull_policy = "Never"
          command           = ["/demo.sh"]
          volume_mount {
            mount_path = "/var/run/csi-secrets"
            name       = "vso-csi"
          }
          env {
            name  = "SECRET_PATH"
            value = "/var/run/csi-secrets"
          }
          env {
            name  = "APP_ROLE_SECRET_IDX"
            value = "0"
          }
          env {
            name  = "VAULT_ADDR"
            value = local.k8s_vault_connection_address
          }
          env {
            name  = "VAULT_NAMESPACE"
            value = local.namespace
          }
          env {
            name  = "VAULT_APP_ROLE_BACKEND"
            value = "auth/${vault_approle_auth_backend_role.csi-secrets[0].backend}"
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_NAME"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_name
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_ID"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_id
          }
        }
        container {
          name              = "app-unlimited"
          image             = "hashicorp/vault-secrets-operator-csi-demo-app:latest"
          image_pull_policy = "Never"
          command           = ["/demo.sh"]
          volume_mount {
            mount_path = "/var/run/csi-secrets"
            name       = "vso-csi"
          }
          env {
            name  = "SECRET_PATH"
            value = "/var/run/csi-secrets"
          }
          env {
            name  = "APP_ROLE_SECRET_IDX"
            value = "1"
          }
          env {
            name  = "VAULT_ADDR"
            value = local.k8s_vault_connection_address
          }
          env {
            name  = "VAULT_NAMESPACE"
            value = local.namespace
          }
          env {
            name  = "VAULT_APP_ROLE_BACKEND"
            value = "auth/${vault_approle_auth_backend_role.csi-secrets[0].backend}"
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_NAME"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_name
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_ID"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_id
          }
        }
        container {
          name              = "control"
          image             = "hashicorp/vault-secrets-operator-csi-demo-app:latest"
          image_pull_policy = "Never"
          command           = ["/control.sh"]
          volume_mount {
            mount_path = "/var/run/csi-secrets"
            name       = "vso-csi"
          }
          env {
            name  = "SECRET_PATH"
            value = "/var/run/csi-secrets"
          }
          env {
            name  = "APP_ROLE_SECRET_IDX"
            value = "0"
          }
          env {
            name  = "VAULT_ADDR"
            value = local.k8s_vault_connection_address
          }
          env {
            name  = "VAULT_NAMESPACE"
            value = local.namespace
          }
          env {
            name  = "VAULT_APP_ROLE_BACKEND"
            value = "auth/${vault_approle_auth_backend_role.csi-secrets[0].backend}"
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_NAME"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_name
          }
          env {
            name  = "VAULT_APP_ROLE_ROLE_ID"
            value = vault_approle_auth_backend_role.csi-secrets[0].role_id
          }
        }
      }
    }
  }
}

resource "kubernetes_manifest" "csi-secrets" {
  count = local.csi_enabled ? 1 : 0
  manifest = {
    metadata = {
      name      = "csi-secret"
      namespace = kubernetes_namespace.demo-ns-vso-csi[0].metadata[0].name
    }

    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "CSISecrets"
    spec = {
      namespace = local.namespace
      vaultAuthRef = {
        name      = kubernetes_manifest.vault-auth-default.manifest.metadata.name
        namespace = kubernetes_manifest.vault-auth-default.manifest.metadata.namespace
      }
      secrets = {
        vaultAppRoleSecretIDs = [
          {
            mount   = vault_approle_auth_backend_role.csi-secrets[0].backend
            role    = vault_approle_auth_backend_role.csi-secrets[0].role_name
            wrapTTL = "10m"
            ttl     = "1h"
            # This container is expected to crash after 10 uses, this is here to
            # demonstrate the CSI driver's after container termination remediation capabilities.
            # Set the value 0 to ensure that this container will only exit after reaching the ttl expiry.
            numUses = 10
            metadata = {
              "app"                            = "vso-csi-app"
              "expect_failure_on_max_num_uses" = "true"
              "wrapped"                        = "true"
              "unlimited_uses"                 = "false"
            }
          },
          {
            mount   = vault_approle_auth_backend_role.csi-secrets[0].backend
            role    = vault_approle_auth_backend_role.csi-secrets[0].role_name
            wrapTTL = "10m"
            ttl     = "1h"
            metadata = {
              "app"                          = "vso-csi-app"
              "expect_failure_on_ttl_expiry" = "true"
              "wrapped"                      = "true"
              "unlimited_uses"               = "true"
            }
          },
          {
            mount = vault_approle_auth_backend_role.csi-secrets[0].backend
            role  = vault_approle_auth_backend_role.csi-secrets[0].role_name
            ttl   = "30m"
            metadata = {
              "app"      = "vso-csi-app"
              "not_used" = "true"
              "wrapped"  = "false"
            }
            cidrList = [
              "192.168.98.0/24"
            ]
            tokenBoundCIDRs = [
              "10.0.0.0/8",
              "192.168.98.0/24",
            ]
          },
          {
            mount = vault_approle_auth_backend_role.csi-secrets[0].backend
            role  = vault_approle_auth_backend_role.csi-secrets[0].role_name
            ttl   = "10m"
            metadata = {
              "app"      = "vso-csi-app"
              "not_used" = "true"
              "wrapped"  = "false"
            }
            cidrList = [
              "192.168.98.0/24"
            ]
            tokenBoundCIDRs = [
              "10.0.0.0/8",
              "192.168.98.0/24",
            ]
          }
        ]
      }
      accessControl = {
        serviceAccountPattern = "^${kubernetes_service_account.vso-csi-app[0].metadata[0].name}$"
        matchPolicy           = "all"
        namespacePatterns = [
          "^${kubernetes_namespace.demo-ns-vso-csi[0].metadata[0].name}$"
        ]
        podNamePatterns = [
          "^vso-csi-app-.+"
        ]
        podLabels = {
          "app.kubernetes.io/component" = "vso-csi-app"
        }
      }
      syncConfig = {
        containerState = {
          namePattern = "^app"
        }
      }
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }

  depends_on = [module.vso-helm]
}

resource "vault_auth_backend" "csi-secrets" {
  count     = local.csi_enabled ? 1 : 0
  namespace = local.namespace
  type      = "approle"
}

resource "vault_approle_auth_backend_role" "csi-secrets" {
  count          = local.csi_enabled ? 1 : 0
  namespace      = local.namespace
  backend        = vault_auth_backend.csi-secrets[0].path
  role_name      = "csi-secrets"
  token_policies = ["default", "dev", "prod"]
}

resource "vault_policy" "csi-secrets" {
  count     = local.csi_enabled ? 1 : 0
  namespace = local.namespace
  name      = "${local.auth_policy}-csi-app"
  policy    = <<EOT
path "auth/${vault_approle_auth_backend_role.csi-secrets[0].backend}/role/${vault_approle_auth_backend_role.csi-secrets[0].role_name}/secret-id" {
  capabilities = ["update"]
}
path "auth/${vault_approle_auth_backend_role.csi-secrets[0].backend}/role/${vault_approle_auth_backend_role.csi-secrets[0].role_name}/role-id" {
  capabilities = ["read"]
}
path "sys/license/status" {
  capabilities = ["read"]
}
EOT
}
