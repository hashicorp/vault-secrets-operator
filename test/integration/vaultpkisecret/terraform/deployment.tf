# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "kubernetes_deployment" "vso" {
  metadata {
    name      = "vso"
    namespace = kubernetes_namespace.tenant-1.metadata[0].name
    labels = {
      test = "vso"
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
        test = "vso"
      }
    }

    template {
      metadata {
        labels = {
          test = "vso"
        }
      }

      spec {
        volume {
          name = "secrets"
          secret {
            secret_name = kubernetes_secret.pki1.metadata[0].name
          }
        }
        container {
          image = "nginx:latest"
          name  = "example"

          volume_mount {
            name       = "secrets"
            mount_path = "/etc/secrets"
            read_only  = true
          }

          resources {
            limits = {
              cpu    = "0.5"
              memory = "512Mi"
            }
            requests = {
              cpu    = "250m"
              memory = "50Mi"
            }
          }

            initial_delay_seconds = 3
            period_seconds        = 3
          }
        }
      }
    }
  }
}
