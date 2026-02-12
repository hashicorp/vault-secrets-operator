# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

variable "k8s_test_namespace" {
  default = "testing"
}

variable "test_service_account" {
  default = ""
}

variable "k8s_vault_connection_address" {}

variable "k8s_config_context" {
  default = "kind-kind"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_host" {
  default = "https://kubernetes.default.svc"
}

variable "k8s_ca_pem" {
  default = ""
}

variable "k8s_token" {
  default = ""
}

variable "vault_oidc_discovery_url" {
  default = "https://kubernetes.default.svc.cluster.local"
}

variable "vault_oidc_ca" {
  default = true
}

variable "vault_kvv2_mount_path" {
  default = "kvv2"
}

variable "vault_test_namespace" {
  default = "tenant-1"
}

# AppRole specific variables
variable "approle_role_name" {
  type    = string
  default = "approle"
}

variable "approle_mount_path" {
  type    = string
  default = "approle"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

# The path to the local helm chart in our repository, this is used by helm to find the Chart.yaml
variable "operator_helm_chart_path" {
  default = "../../../../chart"
}

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}

variable "auth_role" {
  default = "role1"
}

variable "irsa_assumable_role_arn" {
  default = ""
}

variable "aws_region" {
  default = "us-east-2"
}

variable "aws_account_id" {
  default = ""
}

variable "test_aws_access_key_id" {
  description = "AWS_ACCESS_KEY_ID for testing static creds with AWS auth"
  default     = ""
}

variable "test_aws_secret_access_key" {
  description = "AWS_SECRET_ACCESS_KEY for testing static creds with AWS auth"
  default     = ""
  sensitive   = true
}

variable "test_aws_session_token" {
  description = "AWS_SESSION_TOKEN for testing static creds with AWS auth"
  default     = ""
  sensitive   = true
}

variable "aws_static_creds_role" {
  description = "AWS role ARN for the static creds"
  default     = ""
}

variable "run_aws_tests" {
  type    = bool
  default = false
}

variable "run_aws_static_creds_test" {
  type    = bool
  default = false
}
