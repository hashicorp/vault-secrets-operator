# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

output "cluster_arn" {
  description = "ARN for EKS control plane"
  value       = module.eks.cluster_arn
}

output "cluster_certificate_authority" {
  value = data.aws_eks_cluster.cluster.certificate_authority[0].data
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = module.eks.cluster_endpoint
}

output "eks_cluster_token" {
  value     = data.aws_eks_cluster_auth.cluster.token
  sensitive = true
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane"
  value       = module.eks.cluster_security_group_id
}

output "cluster_name" {
  value = module.eks.cluster_name
}

output "eks_node_role_arn" {
  description = "IAM role for the EKS nodes"
  value       = module.eks.eks_managed_node_groups["default_node_group"]["iam_role_arn"]
}
