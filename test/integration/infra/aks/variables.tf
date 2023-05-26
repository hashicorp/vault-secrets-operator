# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

variable "region" {
  default     = "westus2"
  description = "Azure region to deploy the resources"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the AKS cluster"
  type        = string
  default     = "1.25.6"
}

variable "container_repository_name" {
  description = "The Azure container repo name for storing the operator image, prefix to azurecr.io"
  type        = string
  default     = "vso"
}

variable "image_tag_base" {
  description = "The name for the operator image"
  type        = string
  default     = "vault-secrets-operator"
}
