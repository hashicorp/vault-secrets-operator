# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

output "k8s_namespace" {
  value = module.operator.k8s_namespace
}

output "auth_role_operator" {
  value = module.operator.auth_role_operator
}

output "transit_ref" {
  value = module.operator.transit_ref
}

output "transit_path" {
  value = module.operator.transit_path
}

output "transit_key_name" {
  value = module.operator.transit_key_name
}

output "k8s_config_context" {
  value = module.operator.k8s_config_context
}

output "namespace" {
  value = module.operator.namespace
}
