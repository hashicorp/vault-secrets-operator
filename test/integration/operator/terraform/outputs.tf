# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

output "k8s_namespace" {
  value = var.with_eks ? module.operator_eks[0].k8s_namespace : module.operator_kind[0].k8s_namespace
}

output "auth_role_operator" {
  value = var.with_eks ? module.operator_eks[0].auth_role_operator : module.operator_kind[0].auth_role_operator
}

output "transit_ref" {
  value = var.with_eks ? module.operator_eks[0].transit_ref : module.operator_kind[0].transit_ref
}

output "transit_path" {
  value = var.with_eks ? module.operator_eks[0].transit_path : module.operator_kind[0].transit_path
}

output "transit_key_name" {
  value = var.with_eks ? module.operator_eks[0].transit_key_name : module.operator_kind[0].transit_key_name
}

output "k8s_config_context" {
  value = var.with_eks ? module.operator_eks[0].k8s_config_context : module.operator_kind[0].k8s_config_context
}

output "namespace" {
  value = var.with_eks ? module.operator_eks[0].namespace : module.operator_kind[0].namespace
}
