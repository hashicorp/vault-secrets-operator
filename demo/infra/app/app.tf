# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

data "kubernetes_namespace" "operator" {
  metadata {
    name = var.operator_namespace
  }
}

resource "kubernetes_manifest" "vault-connection-default" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
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
    apiVersion = "secrets.hashicorp.com/v1beta1"
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
}

resource "kubernetes_manifest" "vault-dynamic-secret" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "VaultDynamicSecret"
    metadata = {
      name      = "vso-db-demo"
      namespace = kubernetes_namespace.dev.metadata[0].name
      annotations = {
        "myapp.config/postgres-host" = "${local.postgres_host}:5432"
      }
      labels = {
        "myapp/name" : "db"
      }
    }
    spec = {
      namespace      = vault_auth_backend.default.namespace
      mount          = vault_database_secrets_mount.db.path
      path           = local.db_creds_path
      renewalPercent = "66"
      destination = {
        create = true
        name   = "vso-db-demo"
        transformation = {
          transformationRefs = [
            {
              name = kubernetes_manifest.templates.manifest.metadata.name
            }
          ]
        }
      }

      rolloutRestartTargets = [
        {
          kind = "Deployment"
          name = "vso-db-demo"
        }
      ]
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

resource "kubernetes_manifest" "templates" {
  manifest = {
    apiVersion = "secrets.hashicorp.com/v1beta1"
    kind       = "SecretTransformation"
    metadata = {
      name      = "vso-templates"
      namespace = kubernetes_namespace.dev.metadata[0].name
    }
    spec = {
      templates = {
        "app.props" = {
          name = "app.props"
          text = "{{- template \"appProps\" . -}}"
        }
        "app.json" = {
          name = "app.json"
          text = "{{- template \"appJson\" . -}}"
        },
        "app.name" = {
          name = "app.name"
          text = "{{- template \"appName\" . -}}"
        }
        "url" = {
          name = "url"
          text = "{{- template \"dbUrl\" . -}}"
        },
      }
      sourceTemplates = [
        {
          name = "helpers"
          text = <<EOF
{{/*
  create a Java props from SecretInput for this app
*/}}
{{- define "appProps" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- printf "db.host=%s\n" $host -}}
{{- range $k, $v := .Secrets -}}
{{- printf "db.%s=%s\n" $k $v -}}
{{- end -}}
{{- end -}}
{{/*
  create a JSON config from SecretInput for this app
*/}}
{{- define "appJson" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- $copy := .Secrets | mustDeepCopy -}}
{{- $_ := set $copy "host" $host -}}
{{- mustToPrettyJson $copy -}}
{{- end -}}
{{/*
  compose a Postgres URL from SecretInput for this app
*/}}
{{- define "dbUrl" -}}
{{- $host := get .Annotations "myapp.config/postgres-host" -}}
{{- printf "postgresql://%s:%s@%s/postgres?sslmode=disable" (get .Secrets "username") (get .Secrets "password") $host -}}
{{- end -}}
{{/*
  get the app name from the VSO resource's label
*/}}
{{- define "appName" -}}
{{- get .Labels "myapp/name" -}}
{{- end -}}
EOF
        }
      ]
    }
  }

  field_manager {
    # force field manager conflicts to be overridden
    force_conflicts = true
  }
}

resource "kubernetes_deployment" "example" {
  depends_on = [kubernetes_manifest.vault-dynamic-secret]

  metadata {
    name      = "vso-db-demo"
    namespace = local.k8s_namespace
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
            secret_name = "vso-db-demo"
          }
        }
        container {
          image = "postgres:latest"
          name  = "demo"
          command = [
            "sh", "-c", "while : ; do psql $PGURL -c 'select 1;' ; sleep 30; done"
          ]

          env {
            name = "PGURL"
            value_from {
              secret_key_ref {
                name = "vso-db-demo"
                key  = "url"
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
