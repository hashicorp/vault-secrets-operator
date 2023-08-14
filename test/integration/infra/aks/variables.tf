# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "region" {
  default     = "westus2"
  description = "Azure region to deploy the resources"
}

variable "kubernetes_version" {
  description = "Kubernetes version for the AKS cluster"
  type        = string
  default     = "1.25.6"
}

variable "container_repository_prefix" {
  description = "The Azure container repo prefix (.azurecr.io) for storing the operator image"
  type        = string
  default     = "vso"
}

variable "image_tag_base" {
  description = "The name for the operator image"
  type        = string
  default     = "vault-secrets-operator"
}
