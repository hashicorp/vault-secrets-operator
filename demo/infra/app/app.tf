# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "kubernetes_namespace" "operator" {
  metadata {
    name = var.operator_namespace
  }
}

resource "kubernetes_manifest" "vault-connection-default" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultConnection"
    metadata = {
      name      = "default"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      address = "http://vault.vault.svc.cluster.local:8200"
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

resource "kubernetes_manifest" "vault-auth-default" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultAuth"
    metadata = {
      name      = "default"
      namespace = data.kubernetes_namespace.operator.metadata[0].name
    }
    spec = {
      method    = "kubernetes"
      namespace = vault_auth_backend.default.namespace
      mount     = vault_auth_backend.default.path
      kubernetes = {
        role           = vault_kubernetes_auth_backend_role.dev.role_name
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
}

resource "kubernetes_manifest" "vault-dynamic-secret" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "vso-db-demo"
      namespace = kubernetes_namespace.dev.metadata[0].name
    }
    spec = {
      namespace = vault_auth_backend.default.namespace
      mount     = vault_database_secrets_mount.db.path
      path      = local.db_creds_path
      destination = {
        create : false
        name : kubernetes_secret.db.metadata[0].name
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = "vso-db-demo"
        }
      ]
    }
  }
}

resource "kubernetes_manifest" "vault-dynamic-secret-create" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1alpha1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "vso-db-demo-create"
      namespace = kubernetes_namespace.dev.metadata[0].name
    }
    spec = {
      namespace = vault_auth_backend.default.namespace
      mount     = vault_database_secrets_mount.db.path
      path      = local.db_creds_path
      destination = {
        create : true
        name : "vso-db-demo-created"
      }
      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = "vso-db-demo"
        }
      ]
    }
  }
}

resource "kubernetes_secret" "db" {
  metadata {
    name      = "vso-db-demo"
    namespace = kubernetes_namespace.dev.metadata[0].name
  }
}

resource "kubernetes_deployment" "example" {
  metadata {
    name      = "vso-db-demo"
    namespace = kubernetes_namespace.dev.metadata[0].name
    labels = {
      test = "vso-db-demo"
    }
  }


  spec {
    replicas = 3

    strategy {
      rolling_update {
        max_unavailable = "1"
      }
    }

    selector {
      match_labels = {
        test = "vso-db-demo"
      }
    }

    template {
      metadata {
        labels = {
          test = "vso-db-demo"
        }
      }

      spec {
        volume {
          name = "secrets"
          secret {
            secret_name = kubernetes_secret.db.metadata[0].name
          }
        }
        container {
          image = "postgres:latest"
          name  = "demo"
          command = [
            "sh", "-c", "while : ; do psql postgresql://$PGUSERNAME@${local.postgres_host}/postgres?sslmode=disable -c 'select 1;' ; sleep 5; done"
          ]

          env {
            name = "PGPASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.db.metadata[0].name
                key  = "password"
              }
            }
          }

          env {
            name = "PGUSERNAME"
            value_from {
              secret_key_ref {
                name = kubernetes_secret.db.metadata[0].name
                key  = "username"
              }
            }
          }

          volume_mount {
            name       = "secrets"
            mount_path = "/etc/secrets"
            read_only  = true
          }

          resources {
            limits = {
              cpu    = "0.5"
              memory = "64Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "50Mi"
            }
          }
        }
      }
    }
  }
}
