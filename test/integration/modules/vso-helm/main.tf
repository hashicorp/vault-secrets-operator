# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

resource "helm_release" "vault-secrets-operator" {
  name             = "test"
  namespace        = var.operator_namespace
  create_namespace = true
  wait             = true
  chart            = var.operator_helm_chart_path

  # Connection Configuration
  set {
    name  = "defaultVaultConnection.enabled"
    value = var.enable_default_connection
  }
  set {
    name  = "defaultVaultConnection.address"
    value = var.k8s_vault_connection_address
  }
  # Auth Method Configuration
  set {
    name  = "defaultAuthMethod.enabled"
    value = var.enable_default_auth_method
  }
  dynamic "set" {
    for_each = var.k8s_auth_default_mount != "" ? [""] : []
    content {
      name  = "defaultAuthMethod.mount"
      value = var.k8s_auth_default_mount
    }
  }
  set {
    name  = "defaultAuthMethod.namespace"
    value = var.vault_test_namespace
  }
  set {
    name  = "defaultAuthMethod.kubernetes.role"
    value = var.k8s_auth_default_role
  }
  set {
    name  = "defaultAuthMethod.kubernetes.tokenAudiences"
    value = var.k8s_auth_default_token_audiences
  }
  set {
    name  = "controller.manager.image.repository"
    value = var.operator_image_repo
  }
  set {
    name  = "controller.manager.image.tag"
    value = var.operator_image_tag
  }
}
