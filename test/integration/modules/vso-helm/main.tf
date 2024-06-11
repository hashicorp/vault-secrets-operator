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
  set {
    name  = "defaultAuthMethod.mount"
    value = var.k8s_auth_default_mount
  }
  dynamic "set" {
    for_each = var.vault_test_namespace != null ? [""] : []
    content {
      name  = "defaultAuthMethod.namespace"
      value = var.vault_test_namespace
    }
  }
  set_list {
    name  = "defaultAuthMethod.allowedNamespaces"
    value = var.operator_allowednamespaces
  }
  set {
    name  = "defaultAuthMethod.kubernetes.role"
    value = var.k8s_auth_default_role
  }
  set_list {
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
  set {
    name  = "controller.manager.image.tag"
    value = var.operator_image_tag
  }
  set {
    name  = "controller.manager.clientCache.persistenceModel"
    value = var.client_cache_config.persistence_model
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.enabled"
    value = var.client_cache_config.storage_encryption.enabled
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.mount"
    value = var.client_cache_config.storage_encryption.mount
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.transitMount"
    value = var.client_cache_config.storage_encryption.transit_mount
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.keyName"
    value = var.client_cache_config.storage_encryption.key_name
  }
  dynamic "set" {
    for_each = var.client_cache_config.storage_encryption.namespace != null ? [""] : []
    content {
      name  = "controller.manager.clientCache.storageEncryption.namespace"
      value = var.client_cache_config.storage_encryption.namespace
    }
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.method"
    value = var.client_cache_config.storage_encryption.method
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.kubernetes.role"
    value = var.client_cache_config.storage_encryption.kubernetes_auth_role
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.kubernetes.serviceAccount"
    value = var.client_cache_config.storage_encryption.kubernetes_auth_service_account
  }
  set {
    name  = "controller.manager.clientCache.storageEncryption.kubernetes.tokenAudiences"
    value = var.client_cache_config.storage_encryption.kubernetes_auth_token_audiences
  }
  dynamic "set" {
    for_each = var.client_cache_config.revoke_client_cache_on_uninstall ? [""] : []
    content {
      name  = "controller.manager.clientCache.revokeClientCacheOnUninstall"
      value = var.client_cache_config.revoke_client_cache_on_uninstall
    }
  }
  set_list {
    name  = "controller.manager.extraArgs"
    value = var.manager_extra_args
  }
  set_list {
    name  = "controller.rbac.clusterRoleAggregation.viewerRoles"
    value = ["*"]
  }
  set_list {
    name  = "controller.rbac.clusterRoleAggregation.editorRoles"
    value = ["*"]
  }
}
