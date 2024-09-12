# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "k8s_namespace" {
  value = module.operator_common.k8s_namespace
}

output "auth_role_operator" {
  value = module.operator_common.auth_role_operator
}

output "transit_ref" {
  value = module.operator_common.transit_ref
}

output "transit_path" {
  value = module.operator_common.transit_path
}

output "transit_key_name" {
  value = module.operator_common.transit_key_name
}

output "k8s_config_context" {
  value = module.operator_common.k8s_config_context
}

output "namespace" {
  value = module.operator_common.namespace
}
