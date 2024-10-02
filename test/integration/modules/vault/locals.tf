# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  vault_image_tag_ent    = var.vault_image_tag_ent
  vault_image_repository = var.vault_enterprise ? var.vault_image_repo_ent : var.vault_image_repo
  vault_license          = var.vault_enterprise ? (var.vault_license != "" ? var.vault_license : file(var.vault_license_path)) : ""
  ha_replicas            = var.vault_instance_count

  helm_chart_settings = {
    "server.ha.enabled"             = "true"
    "server.ha.raft.enabled"        = "true"
    "server.resources.requests.cpu" = "50m"
    "server.limits.memory"          = "200m"
    "server.limits.cpu"             = "200m"
    "server.ha.raft.config"         = file("${abspath(path.module)}/raft-config.hcl")
    "server.dataStorage.size"       = "100m"
  }
  enos_helm_chart_settings = var.with_enos ? local.helm_chart_settings : {}

  vault_address    = "http://127.0.0.1:8200"
  instance_indexes = var.with_enos && var.vault_instance_count != null ? [for idx in range(var.vault_instance_count) : tostring(idx)] : []

  leader_idx    = var.with_enos && length(local.instance_indexes) > 0 ? local.instance_indexes[0] : null
  followers_idx = var.with_enos && local.leader_idx != null ? toset(slice(local.instance_indexes, 1, var.vault_instance_count)) : toset([])
}


