# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "kubernetes_version" {
  type    = string
  default = "1.30"
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-2"
}

variable "eks_node_group_instance_count" {
  default = 2
}