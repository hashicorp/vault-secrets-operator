# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

output "cluster_arn" {
  description = "ARN for EKS control plane"
  value       = module.eks.cluster_arn
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "ecr_url" {
  description = "Endpoint for ECR"
  value       = aws_ecr_repository.vault-secrets-operator.repository_url
}

output "ecr_name" {
  description = "ECR repository name"
  value       = aws_ecr_repository.vault-secrets-operator.name
}

output "oidc_discovery_url" {
  description = "EKS OIDC discovery URL"
  value       = module.eks.cluster_oidc_issuer_url
}
