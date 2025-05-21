# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  name = "vso-${random_string.suffix.result}"
}

resource "random_string" "suffix" {
  length  = 4
  special = false
  upper   = false
}

resource "helm_release" "vault-secrets-operator" {
  name             = local.name
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
  dynamic "set" {
    for_each = var.cpu_limits != "" ? [""] : []
    content {
      name  = "controller.manager.resources.limits.cpu"
      value = var.cpu_limits
    }
  }
  dynamic "set" {
    for_each = var.memory_limits != "" ? [""] : []
    content {
      name  = "controller.manager.resources.limits.memory"
      value = var.memory_limits
    }
  }
  dynamic "set" {
    for_each = var.cpu_requests != "" ? [""] : []
    content {
      name  = "controller.manager.resources.requests.cpu"
      value = var.cpu_requests
    }
  }
  dynamic "set" {
    for_each = var.memory_requests != "" ? [""] : []
    content {
      name  = "controller.manager.resources.requests.memory"
      value = var.memory_requests
    }
  }

  # metrics service configuration
  set {
    name = "metricsService.ports[0].name"
    value = var.metrics_service.ports[0].name
  }
  set {
    name = "metricsService.ports[0].port"
    value = var.metrics_service.ports[0].port
  }
  set {
    name = "metricsService.ports[0].protocol"
    value = var.metrics_service.ports[0].protocol
  }
  set {
    name = "metricsService.ports[0].targetPort"
    value = var.metrics_service.ports[0].targetPort
  }
  set {
    name = "metricsService.type"
    value = var.metrics_service.type
  }

  # service monitor configuration
  set {
    name  = "telemetry.serviceMonitor.enabled"
    value = var.telemetry.service_monitor.enabled
  }
  set {
    name  = "telemetry.serviceMonitor.selectors"
    value = var.telemetry.service_monitor.enabled
  }
  set {
    name  = "telemetry.serviceMonitor.scheme"
    value = var.telemetry.service_monitor.scheme
  }
  set {
    name  = "telemetry.serviceMonitor.port"
    value = var.telemetry.service_monitor.port
  }
  set {
    name  = "telemetry.serviceMonitor.bearerTokenFile"
    value = var.telemetry.service_monitor.bearerTokenFile
  }
  set {
    name  = "telemetry.serviceMonitor.interval"
    value = var.telemetry.service_monitor.interval
  }
  set {
    name  = "telemetry.serviceMonitor.scrapeTimeout"
    value = var.telemetry.service_monitor.scrapeTimeout
  }
}
