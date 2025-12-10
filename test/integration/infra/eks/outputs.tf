# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

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

output "irsa_role" {
  description = "IRSA assumable AWS role"
  value       = module.iam_assumable_role.iam_role_arn
}

output "eks_node_role_arn" {
  description = "IAM role for the EKS nodes"
  value       = module.eks.eks_managed_node_groups["default_node_group"]["iam_role_arn"]
}

output "account_id" {
  description = "AWS account id for setting up auth with the instance profile"
  value       = data.aws_caller_identity.current.account_id
}
