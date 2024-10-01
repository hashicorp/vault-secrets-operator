# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "cluster_name" {
  description = "EKS cluster name"
  type = string
}

variable "prometheus_namespace" {
  description = "K8s namespace to deploy prometheus server"
  type = string
}

variable ""
variable "with_eks" {
  type    = bool
  default = false
}

