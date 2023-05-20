#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

# Function to check if env var exists
check_env_exists() {
    local file="$1"
    local current_dir=$(pwd)

    # Prepend current directory if the file path is relative
    if [[ "$file" != /* ]]; then
        file="$current_dir/$file"
    fi

    if [[ ! -f "$file" ]]; then
        echo "Error: File '$file' does not exist. Please make sure the kubernetes cluster is created & running!"
        exit 1
    fi
}

# Function to check if a command exists
check_command_exists() {
    local command="$1"
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Error: Please install $command before proceeding further!"
        exit 1
    fi
}

check_env_exists "$1"
echo "$1 environment exists, loading values..."
source $1

check_command_exists "$2"
echo "$2 command exists, proceeding further..."

# Execute commands based on user input
case "$3" in
    "gcp-k8s")
        echo "Getting GKE credentials..."
        gcloud container clusters get-credentials "$GKE_CLUSTER_NAME" --region "$GCP_REGION"
        ;;
    "gcp-push")
        echo "Pushing the operator image to Google Artifact Registry..."
        IMG="$IMAGE_TAG_BASE":"0.0.0-dev"
        IMG="$IMG" make ci-build ci-docker-build
        gcloud auth configure-docker "$GCP_REGION"-docker.pkg.dev
	    docker push "$IMG"
        ;;
    "gcp-test")
        echo "Testing the operator against GKE..."
        K8S_CLUSTER_CONTEXT="gke_${GCP_PROJ_ID}_${GCP_REGION}_${GKE_CLUSTER_NAME}"
        IMG="$IMAGE_TAG_BASE":"0.0.0-dev"
	    make port-forward &
	    K8S_CLUSTER_CONTEXT="$K8S_CLUSTER_CONTEXT" IMAGE_TAG_BASE="$IMAGE_TAG_BASE" IMG="$IMG" TF_VAR_vault_oidc_discovery_url="$GKE_OIDC_URL" TF_VAR_vault_oidc_ca="false" make integration-test
        ;;
    *)
        echo "Invalid command: $command, cloud helper script not invoked properly, exiting..."
        exit 1
        ;;
esac