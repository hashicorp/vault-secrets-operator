# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "operator_namespace" {
  default = "vault-secrets-operator-system"
}

variable "name_prefix" {
  type = string
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "k8s_host" {
  default = "https://kubernetes.default.svc"
}

variable "k8s_vault_namespace" {
  type = string
}

variable "k8s_vault_service_account" {
  type = string
}

variable "postgres_secret_name" {
  default = "postgres-postgresql"
}

variable "vault_enterprise" {
  type    = bool
  default = false
}

variable "vault_token_period" {
  default = 30
}

variable "vault_db_default_lease_ttl" {
  default = 60
}

variable "vault_address" {}
variable "vault_token" {}

variable "deploy_operator_via_helm" {
  type    = bool
  default = false
}

variable "operator_helm_chart_path" {
  default = "../../../chart"
}

variable "enable_default_connection" {
  type    = bool
  default = false
}

variable "enable_default_auth_method" {
  type    = bool
  default = false
}

variable "k8s_vault_connection_address" {
  default = ""
}

variable "operator_image_repo" {
  default = "hashicorp/vault-secrets-operator"
}

variable "operator_image_tag" {
  default = "0.0.0-dev"
}

variable "with_static_role_scheduled" {
  type    = bool
  default = true
}

# vault_xns is a boolean that determines if the test should run with cross-namespace support
# requires vault_enterprise to be true
variable "with_xns" {
  type    = bool
  default = false
}

variable "chart_postgres" {
  type    = string
  default = ""
}

variable "use_events" {
  type    = bool
  default = false
}

# --- HVD (HCP Vault Dedicated) support ---
# use_hvd switches Postgres from an in-cluster Helm release to an EC2 instance
# that HVD can reach over the public internet. Default false = existing
# kind behavior is completely unaffected.
variable "use_hvd" {
  type    = bool
  default = false
}

variable "vault_namespace" {
  description = "Vault namespace for HVD. Empty = root (kind)."
  type        = string
  default     = ""
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "ec2_ami_id" {
  description = "AMI ID for the EC2 Postgres instance (HVD only). Must be an EDR-compliant hc-base AMI in aws_region. If empty (default), the latest available hc-base-al2023-x86_64-* AMI is looked up automatically."
  type        = string
  default     = ""
}

variable "ec2_instance_type" {
  type    = string
  default = "t3.small"
}

variable "ec2_postgres_password" {
  description = "Password to set for the EC2 Postgres superuser (HVD only). If empty (default), a random password is generated."
  type        = string
  default     = ""
  sensitive   = true
}

variable "hvd_egress_cidr" {
  description = "CIDR block allowed to reach the EC2 Postgres instance on port 5432 (HVD's outbound egress range). Defaults to unrestricted since this is short-lived test infra torn down at the end of each run; tighten for any longer-lived use."
  type        = string
  default     = "0.0.0.0/0"
}

variable "ssh_ingress_cidr" {
  description = "CIDR block allowed to SSH into the EC2 Postgres instance (the test runner's IP). If empty (default), the runner's current public IP is looked up automatically."
  type        = string
  default     = ""
}
