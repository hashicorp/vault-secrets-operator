# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  vault_image_tag_ent    = var.vault_image_tag_ent
  vault_image_repository = var.vault_enterprise ? var.vault_image_repo_ent : var.vault_image_repo
}
