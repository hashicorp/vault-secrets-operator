# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

module "vault" {
  source               = "../../../../modules/vault"
  vault_license_path   = var.vault_license_path
  vault_license        = var.vault_license
  k8s_namespace        = var.k8s_namespace
  k8s_service_account  = var.k8s_service_account
  k8s_config_context   = var.k8s_config_context
  k8s_config_path      = var.k8s_config_path
  vault_image_repo_ent = var.vault_image_repo_ent
  vault_image_tag_ent  = var.vault_image_tag_ent
  vault_chart_version  = var.vault_chart_version
  with_enos            = true
  kubeconfig_base64 = filebase64("~/.kube/config")
  context_name      = "arn:aws:eks:us-east-2:104902550792:cluster/eks-on8b"
  vault_instance_count = 1
#   context_name = var.context_name
#   kubeconfig_base64 = var.kubeconfig_base64
}