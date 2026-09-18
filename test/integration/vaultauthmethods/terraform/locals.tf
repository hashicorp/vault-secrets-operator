# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

locals {
  # HVD path: null — the vault provider is already scoped to the target
  # namespace via the VAULT_NAMESPACE env var (set by the test runner), so
  # resources must NOT also set an explicit namespace attribute, or the
  # provider concatenates the two into a nested (and invalid) "admin/admin".
  # Enterprise (non-HVD) path: use the auto-created vault_namespace.test child namespace. 
  # Community path: no namespace.
  # Order matters: vault_namespace != "" must be checked first so that
  # vault_namespace.test[0] (count-guarded to 0 under HVD) is never evaluated.
  namespace = (
    var.vault_namespace != "" ? null :
    var.vault_enterprise ? vault_namespace.test[0].path_fq :
    null
  )
}
