# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  default     = "West US 2"
  description = "Azure region to deploy the resources"
}

variable "appId" {
  description = "Azure Kubernetes Service Cluster service principal"
}

variable "password" {
  description = "Azure Kubernetes Service Cluster password"
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