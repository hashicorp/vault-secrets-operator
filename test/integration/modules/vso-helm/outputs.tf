# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "namespace" {
  value = helm_release.vault-secrets-operator.namespace
}
