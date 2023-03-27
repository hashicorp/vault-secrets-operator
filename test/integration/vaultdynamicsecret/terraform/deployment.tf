# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "kubernetes_deployment" "vso" {
  metadata {
    name      = "vso"
    namespace = kubernetes_namespace.dev.metadata[0].name
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
        dynamic "volume" {
          for_each = kubernetes_secret.db
          content {
            name = "secrets-${volume.value.metadata[0].name}"
            secret {
              secret_name = volume.value.metadata[0].name
            }
          }
        }
        container {
          image = "nginx:latest"
          name  = "example"

          dynamic "volume_mount" {
            for_each = kubernetes_secret.db
            content {
              name       = "secrets-${volume_mount.value.metadata[0].name}"
              mount_path = "/etc/secrets-${volume_mount.value.metadata[0].name}"
              read_only  = true
            }
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
