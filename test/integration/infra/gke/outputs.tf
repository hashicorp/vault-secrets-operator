# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "region" {
  value       = var.region
  description = "Google Cloud Region to deploy resources"
}

output "project_id" {
  value       = var.project_id
  description = "Google Cloud Project Id"
}

output "kubernetes_cluster_name" {
  value       = google_container_cluster.primary.name
  description = "GKE Cluster Name"
}

output "gar_name" {
  value       = google_artifact_registry_repository.vault-secrets-operator.name
  description = "Google artifact registry repository"
}

output "oidc_discovery_url" {
  value       = format("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s", var.project_id, var.region, local.cluster_name)
  description = "GKE OIDC discovery URL"
}

resource "local_file" "env_file" {
  filename = "${path.module}/output.env"
  content = <<EOT
GKE_OIDC_URL=${format("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s", var.project_id, var.region, local.cluster_name)}
GCP_GAR_NAME=${google_artifact_registry_repository.vault-secrets-operator.name}
GKE_CLUSTER_NAME=${google_container_cluster.primary.name}
GCP_PROJ_ID=${var.project_id}
GCP_REGION=${var.region}
IMAGE_TAG_BASE=${format("%s-docker.pkg.dev/%s/${google_artifact_registry_repository.vault-secrets-operator.name}/vault-secrets-operator", var.region, var.project_id)}
EOT
}
