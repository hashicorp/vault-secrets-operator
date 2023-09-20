# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.16.1"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "2.8.0"
    }
  }
}

provider "kubernetes" {
  config_context = var.k8s_config_context
  config_path    = var.k8s_config_path
}

provider "helm" {
  kubernetes {
    config_context = var.k8s_config_context
    config_path    = var.k8s_config_path
  }
}

resource "kubernetes_namespace" "demo" {
  metadata {
    name = local.k8s_namespace
  }
}

resource "kubernetes_secret" "sp" {
  metadata {
    name      = "${var.name_prefix}-sp"
    namespace = kubernetes_namespace.demo.metadata[0].name
  }
  data = {
    "clientID"  = var.hcp_client_id
    "clientKey" = var.hcp_client_secret
  }
}

resource "local_file" "hcp-auth" {
  content = <<EOT
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: HCPAuth
metadata:
  name: default
  namespace: ${local.operator_namespace}
spec:
  organizationID: ${var.hcp_organization_id}
  projectID: ${var.hcp_project_id}
  servicePrincipal:
    secretRef: ${kubernetes_secret.sp.metadata[0].name}
---
apiVersion: secrets.hashicorp.com/v1beta1
kind: HCPVaultSecretsApp
metadata:
  name: hcpvs-demo
  namespace: ${kubernetes_namespace.demo.metadata[0].name}
spec:
  appName: ${var.vault_secret_app_name}
  destination:
    create: true
    labels:
      hvs: "true"
    name: ${var.name_prefix}-dest-secret
  refreshAfter: 3s
EOT

  filename = "scratch/demo.yaml"
}

resource "local_file" "demo-script" {
  filename = "scratch/demo.sh"
  content  = <<EOT
#!/bin/sh
set -e
kubectl apply -f $(dirname $0)/demo.yaml &> /dev/null
echo "run the following command to dump the HVS Secret data from K8s"
echo "kubectl get secret --namespace ${kubernetes_namespace.demo.metadata[0].name} ${var.name_prefix}-dest-secret -o yaml"
EOT
}

module "vso-helm" {
  source                     = "../../test/integration/modules/vso-helm"
  operator_namespace         = var.operator_namespace
  enable_default_auth_method = false
  enable_default_connection  = false
  chart                      = var.chart
  chart_version              = "0.3.0-rc.1"
  operator_image_tag         = "0.3.0-rc.1"
}
