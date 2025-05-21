# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "vault_license_path" {
  default = ""
}

variable "vault_license" {
  default = ""
}

variable "k8s_namespace" {
  default = "vault"
}

variable "k8s_service_account" {
  default = "vault"
}

variable "k8s_config_context" {
  default = "kind-vault-secrets-operator"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "vault_image_repo" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault"
}

variable "vault_image_repo_ent" {
  default = "docker.mirror.hashicorp.services/hashicorp/vault-enterprise"
}

variable "vault_image_tag" {
  default = "1.17"
}

variable "vault_image_tag_ent" {
  default = "1.17-ent"
}

variable "vault_enterprise" {
  type    = bool
  default = true
}

variable "vault_chart_version" {
  default = "0.28.1"
}

variable "install_kube_prometheus" {
  type    = bool
  default = false
}

variable "metrics_server_enabled" {
  type    = bool
  default = true
}

variable "server_telemetry" {
  type = object({
    service_monitor = object({
      enabled       = bool
      selectors     = map(string)
      interval      = string
      scrapeTimeout = string

      # The tlsConfig stanza actually contains more fields than declared here
      # For scale testing purpose, we use `ca` stanza
      # https://github.com/hashicorp/vault-helm/blob/3ab634e6ea3ec344688fac5cb5a93dad157bd537/values.yaml#L1297-L1305
      tlsConfig = object({
        ca = object({
          secret = object({
            name = string
            key  = string
          })
        })
      })
    })
  })

  default = {
    service_monitor = {
      enabled         = true
      selectors       = {}
      interval        = "30s"
      scrapeTimeout   = "10s"
      tlsConfig       = {}
    }
  }
}

variable "server_standalone" {
  type = object({
    config = string
  })

  default = {
      config =<<EOF
ui = true

listener "tcp" {
  tls_disable = 1
  address = "[::]:8200"
  cluster_address = "[::]:8201"
  # Enable unauthenticated metrics access (necessary for Prometheus Operator)
  telemetry {
    unauthenticated_metrics_access = "true"
  }
}
storage "file" {
  path = "/vault/data"
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}
EOF
  }
}
