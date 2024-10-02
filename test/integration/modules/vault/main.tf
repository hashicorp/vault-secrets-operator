# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
terraform {
  required_providers {
    enos = {
      source = "registry.terraform.io/hashicorp-forge/enos"
      version = ">= 0.5.5"
    }
  }
}

resource "kubernetes_namespace" "vault" {
  metadata {
    name = var.k8s_namespace
  }
}

resource "kubernetes_secret" "vault_license" {
  count = var.vault_enterprise ? 1 : 0
  metadata {
    namespace = kubernetes_namespace.vault.metadata[0].name
    name      = "vault-license"
  }
  data = {
    license = local.vault_license
  }
}

resource "helm_release" "vault" {
  version          = var.vault_chart_version
  name             = "vault"
  namespace        = kubernetes_namespace.vault.metadata[0].name
  create_namespace = false
  wait             = true
  wait_for_jobs    = true

  repository = "https://helm.releases.hashicorp.com"
  chart      = "vault"

  set {
    name  = "server.dev.enabled"
    value = "true"
  }
  set {
    name  = "server.image.repository"
    value = local.vault_image_repository
  }
  set {
    name  = "server.image.tag"
    value = local.vault_image_tag_ent
  }
  set {
    name  = "server.logLevel"
    value = "debug"
  }
  set {
    name  = "server.serviceAccount.name"
    value = var.k8s_service_account
  }
  set {
    name  = "injector.enabled"
    value = "false"
  }

  dynamic "set" {
    for_each = var.vault_enterprise ? [""] : []
    content {
      name  = "server.enterpriseLicense.secretName"
      value = kubernetes_secret.vault_license[0].metadata[0].name
    }
  }

  dynamic "set" {
    for_each = local.ha_replicas != null ? [""] : []
    content {
      name  = "server.ha.replicas"
      value = local.ha_replicas
    }
  }

  dynamic "set" {
    for_each = local.enos_helm_chart_settings
    content {
      name  = set.key
      value = set.value
    }
  }
}

resource "kubernetes_cluster_role_binding" "oidc-reviewer" {
  metadata {
    name = "oidc-reviewer-cluster-role-binding"
  }
  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = "system:service-account-issuer-discovery"
  }
  subject {
    kind = "Group"
    name = "system:unauthenticated"
  }
}

// This is a derivative of:
// https://github.com/hashicorp/vault/blob/main/enos/modules/k8s_deploy_vault/main.tf
data "enos_kubernetes_pods" "vault_pods" {
  count             = var.with_enos ? 1 : 0
  kubeconfig_base64 = var.kubeconfig_base64
  context_name      = var.context_name
  namespace         = helm_release.vault.namespace
  label_selectors = [
    "app.kubernetes.io/name=vault",
    "component=server"
  ]

  depends_on = [helm_release.vault]
}

resource "enos_vault_init" "leader" {
  count      = var.with_enos ? 1 : 0
  bin_path   = "/bin/vault"
  vault_addr = local.vault_address

  key_shares    = 5
  key_threshold = 3

  transport = {
    kubernetes = {
      kubeconfig_base64 = var.kubeconfig_base64
      context_name      = var.context_name
      pod               = data.enos_kubernetes_pods.vault_pods[0].pods[local.leader_idx].name
      namespace         = data.enos_kubernetes_pods.vault_pods[0].pods[local.leader_idx].namespace
    }
  }
}

resource "enos_vault_unseal" "leader" {
  count       = var.with_enos ? 1 : 0
  bin_path    = "/bin/vault"
  vault_addr  = local.vault_address
  seal_type   = "shamir"
  //unseal_keys = enos_vault_init.leader[*].unseal_keys_b64
  unseal_keys = flatten(enos_vault_init.leader[0].unseal_keys_b64)

  transport = {
    kubernetes = {
      kubeconfig_base64 = var.kubeconfig_base64
      context_name      = var.context_name
      pod               = data.enos_kubernetes_pods.vault_pods[0].pods[local.leader_idx].name
      namespace         = data.enos_kubernetes_pods.vault_pods[0].pods[local.leader_idx].namespace
    }
  }

  depends_on = [enos_vault_init.leader]
}

// We need to manually join the followers since the join request must only happen after the leader
// has been initialized. We could use retry join, but in that case we'd need to restart the follower
// pods once the leader is setup. The default helm deployment configuration for an HA cluster as
// documented here: https://learn.hashicorp.com/tutorials/vault/kubernetes-raft-deployment-guide#configure-vault-helm-chart
// uses a liveness probe that automatically restarts nodes that are not healthy. This works well for
// clusters that are configured with auto-unseal as eventually the nodes would join and unseal.
resource "enos_remote_exec" "raft_join" {
  for_each = var.with_enos ? local.followers_idx : []

  inline = [
    // asserts that vault is ready
    "for i in 1 2 3 4 5; do vault status > /dev/null 2>&1 && break || sleep 5; done",
    // joins the follower to the leader
    "vault operator raft join http://vault-0.vault-internal:8200"
  ]

  transport = {
    kubernetes = {
      kubeconfig_base64 = var.kubeconfig_base64
      context_name      = var.context_name
      pod               = data.enos_kubernetes_pods.vault_pods[0].pods[each.key].name
      namespace         = data.enos_kubernetes_pods.vault_pods[0].pods[each.key].namespace
    }
  }

  depends_on = [enos_vault_unseal.leader]
}


resource "enos_vault_unseal" "followers" {
  for_each = var.with_enos ? local.followers_idx : []

  bin_path    = "/bin/vault"
  vault_addr  = local.vault_address
  seal_type   = "shamir"
  unseal_keys = enos_vault_init.leader[0].unseal_keys_b64

  transport = {
    kubernetes = {
      kubeconfig_base64 = var.kubeconfig_base64
      context_name      = var.context_name
      pod               = data.enos_kubernetes_pods.vault_pods[0].pods[each.key].name
      namespace         = data.enos_kubernetes_pods.vault_pods[0].pods[each.key].namespace
    }
  }

  depends_on = [enos_remote_exec.raft_join]
}
