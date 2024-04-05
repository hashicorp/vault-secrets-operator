# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  cluster_name = "gke-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

# VPC
resource "google_compute_network" "vpc" {
  name                    = "vpc-${local.cluster_name}"
  auto_create_subnetworks = "false"
}

# Subnet
resource "google_compute_subnetwork" "subnet" {
  name          = "subnet-${local.cluster_name}"
  region        = var.region
  network       = google_compute_network.vpc.name
  ip_cidr_range = "10.10.0.0/24"
}

# GKE cluster
resource "google_container_cluster" "primary" {
  name     = local.cluster_name
  location = var.region

  node_locations           = ["${var.region}-a"]
  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_network.vpc.name
  subnetwork = google_compute_subnetwork.subnet.name

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  deletion_protection = false

  depends_on = [google_project_iam_member.default_gar_reader,
  google_project_iam_member.default_gar_writer]
}

# Separately Managed Node Pool
resource "google_container_node_pool" "primary_nodes" {
  name       = google_container_cluster.primary.name
  cluster    = google_container_cluster.primary.name
  location   = var.region
  node_count = var.gke_num_nodes
  autoscaling {
    min_node_count = 1
    max_node_count = 3
  }

  node_config {
    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = {
      env = local.cluster_name
    }

    machine_type    = "n1-standard-2"
    service_account = google_service_account.default.email
    tags            = ["gke-node", local.cluster_name]
    metadata = {
      disable-legacy-endpoints = "true"
    }
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# Create a private Google Artifact Registry
resource "google_artifact_registry_repository" "vault-secrets-operator" {
  location      = var.region
  repository_id = "vault-secrets-operator-${local.cluster_name}"
  description   = "A private docker repository to store the operator image"
  format        = "DOCKER"
}

# Create a new Service account for pulling the image from private repository
resource "google_service_account" "default" {
  account_id   = "sa-${local.cluster_name}"
  display_name = "GKE Service Account"
}

resource "google_project_iam_member" "default_gar_writer" {
  project = var.project_id
  role    = "roles/storage.objectViewer"
  member  = "serviceAccount:${google_service_account.default.email}"
}

# Give it appropriate permissions to pull the image
resource "google_project_iam_member" "default_gar_reader" {
  project = var.project_id
  role    = "roles/artifactregistry.reader"
  member  = "serviceAccount:${google_service_account.default.email}"
}

resource "local_file" "env_file" {
  filename = "${path.module}/outputs.env"
  content  = <<EOT
GKE_OIDC_URL=${format("https://container.googleapis.com/v1/projects/%s/locations/%s/clusters/%s", var.project_id, var.region, local.cluster_name)}
GCP_GAR_NAME=${google_artifact_registry_repository.vault-secrets-operator.name}
GKE_CLUSTER_NAME=${google_container_cluster.primary.name}
GCP_PROJECT=${var.project_id}
GCP_REGION=${var.region}
IMAGE_TAG_BASE=${format("%s-docker.pkg.dev/%s/${google_artifact_registry_repository.vault-secrets-operator.name}/vault-secrets-operator", var.region, var.project_id)}
K8S_CLUSTER_CONTEXT=${format("gke_%s_%s_%s", var.project_id, var.region, local.cluster_name)}
EOT
}
