# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "prometheus_workspace_arn" {
  description = "ARN for the prometheus workspace"
  value       = aws_prometheus_workspace.workspace.arn
}

output "prometheus_workspace_id" {
  description = "ID of the prometheus workspace"
  value       = aws_prometheus_workspace.workspace.id
}

output "prometheus_endpoint" {
  description = "Prometheus endpoint of the workspace"
  value       = aws_prometheus_workspace.workspace.prometheus_endpoint
}

output "prometheus_workspace_tag_name" {
  description = "Tagged name of the workspace"
  value       = aws_prometheus_workspace.workspace.tags_all[]
}