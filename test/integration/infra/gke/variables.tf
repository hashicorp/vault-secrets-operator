# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "gke_num_nodes" {
  default     = 1
  description = "number of gke nodes"
}

variable "project_id" {
  description = "project id"
}

variable "region" {
  description = "region"
  default     = "us-west1"
}