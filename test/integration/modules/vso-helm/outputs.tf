# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1

output "operator_namespace" {
  value = helm_release.vault-secrets-operator.namespace
}
