# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "operator_namespace" {
  value = helm_release.vault-secrets-operator.namespace
}
