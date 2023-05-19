# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "rg" {
  default     = "rg-vso"
  description = "Azure Resource Group attached to the region"
}

variable "region" {
  default     = "West US 2"
  description = "Azure region to deploy the resources"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the AKS cluster"
  type        = string
  default     = "1.25.6"
}

variable "container_repository_name" {
  description = "The ACR container repository name for storing the operator image"
  type        = string
  default     = "vaultsecretsoperator"
}