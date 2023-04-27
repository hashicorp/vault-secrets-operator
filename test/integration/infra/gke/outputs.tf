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