# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

resource "kubernetes_deployment" "vso" {
  metadata {
    name      = "vso"
    namespace = kubernetes_namespace.app.metadata[0].name
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
          image             = "busybox"
          name              = "example"
          image_pull_policy = "IfNotPresent"
          command           = ["/bin/sh", "-c", "while :; do echo hello; sleep 10; done"]

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
        }
      }
    }
  }
}
