#!/usr/bin/env bats

#
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

#--------------------------------------------------------------------
# clusterrole-aggregated-viewer-csi-driver tests

@test "CSIDriver/ClusterRoleAggregated: not created when csi.enabled is false - default" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/clusterrole-aggregated-viewer-csi-driver.yaml \
    . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver/ClusterRoleAggregated: name is correct when csi.enabled is true" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/clusterrole-aggregated-viewer-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.metadata.name' | tee /dev/stderr)

  [ "${object}" = "release-name-vault-secrets-operator-aggregate-role-viewer-csi-driver" ]
}

@test "CSIDriver/ClusterRoleAggregated: metadata labels are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/clusterrole-aggregated-viewer-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.metadata.labels' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "8" ]
  actual=$(echo "$object" | yq '."app.kubernetes.io/component"' | tee /dev/stderr)
  [ "${actual}" = "rbac" ]
  actual=$(echo "$object" | yq '."vso.hashicorp.com/role-instance"' | tee /dev/stderr)
  [ "${actual}" = "aggregate-role-viewer" ]
  actual=$(echo "$object" | yq '."rbac.authorization.k8s.io/aggregate-to-view"' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

@test "CSIDriver/ClusterRoleAggregated: aggregation rules correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/clusterrole-aggregated-viewer-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" | yq '.[0].matchLabels | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" |
    yq '.[0].matchLabels."vso.hashicorp.com/aggregate-to-viewer"' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# csisecrets_editor_role tests

@test "CSIDriver/ClusterRoleEditor: metadata name is correct" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_editor_role.yaml \
    . | tee /dev/stderr |
    yq '.metadata.name' | tee /dev/stderr)

  [ "${object}" = "release-name-vault-secrets-operator-csisecrets-editor-role" ]
}

@test "CSIDriver/ClusterRoleEditor: metadata labels are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_editor_role.yaml \
    . | tee /dev/stderr |
    yq '.metadata.labels' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "8" ]
  actual=$(echo "$object" | yq '."app.kubernetes.io/component"' | tee /dev/stderr)
  [ "${actual}" = "rbac" ]
  actual=$(echo "$object" | yq '."vso.hashicorp.com/role-instance"' | tee /dev/stderr)
  [ "${actual}" = "csisecrets-editor-role" ]
  actual=$(echo "$object" | yq '."vso.hashicorp.com/aggregate-to-editor"' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

@test "CSIDriver/ClusterRoleEditor: rules are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_editor_role.yaml \
    . | tee /dev/stderr |
    yq '.rules' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]

  actual=$(echo "$object" | yq '.[0].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "secrets.hashicorp.com" ]
  actual=$(echo "$object" | yq '.[0].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "csisecrets" ]
  actual=$(echo "$object" | yq '.[0].verbs | join(",")' | tee /dev/stderr)
  [ "${actual}" = "create,delete,get,list,patch,update,watch" ]

  actual=$(echo "$object" | yq '.[1].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "secrets.hashicorp.com" ]
  actual=$(echo "$object" | yq '.[1].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "csisecrets/status" ]
  actual=$(echo "$object" | yq '.[1].verbs[0]' | tee /dev/stderr)
  [ "${actual}" = "get" ]
}

#--------------------------------------------------------------------
# csisecrets_viewer_role tests

@test "CSIDriver/ClusterRoleViewer: metadata name is correct" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_viewer_role.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.metadata.name' | tee /dev/stderr)

  [ "${object}" = "release-name-vault-secrets-operator-csisecrets-viewer-role" ]
}

@test "CSIDriver/ClusterRoleViewer: metadata labels are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_viewer_role.yaml \
    . | tee /dev/stderr |
    yq '.metadata.labels' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "8" ]
  actual=$(echo "$object" | yq '."app.kubernetes.io/component"' | tee /dev/stderr)
  [ "${actual}" = "rbac" ]
  actual=$(echo "$object" | yq '."vso.hashicorp.com/role-instance"' | tee /dev/stderr)
  [ "${actual}" = "csisecrets-viewer-role" ]
  actual=$(echo "$object" | yq '."vso.hashicorp.com/aggregate-to-viewer"' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

@test "CSIDriver/ClusterRoleViewer: rules are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csisecrets_viewer_role.yaml \
    . | tee /dev/stderr |
    yq '.rules' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]

  actual=$(echo "$object" | yq '.[0].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "secrets.hashicorp.com" ]
  actual=$(echo "$object" | yq '.[0].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "csisecrets" ]
  actual=$(echo "$object" | yq '.[0].verbs | join(",")' | tee /dev/stderr)
  [ "${actual}" = "get,list,watch" ]

  actual=$(echo "$object" | yq '.[1].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "secrets.hashicorp.com" ]
  actual=$(echo "$object" | yq '.[1].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "csisecrets/status" ]
  actual=$(echo "$object" | yq '.[1].verbs[0]' | tee /dev/stderr)
  [ "${actual}" = "get" ]
}

#--------------------------------------------------------------------
# cluster-role-csi-driver tests

@test "CSIDriver/ClusterRole: not created when csi.enabled is false - default" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/cluster-role-csi-driver.yaml \
    . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver/ClusterRole: metadata name is correct" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.metadata.name' | tee /dev/stderr)

  [ "${object}" = "release-name-vault-secrets-operator-csi-driver-role" ]
}

@test "CSIDriver/ClusterRole: metadata labels are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.metadata.labels' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "6" ]
  actual=$(echo "$object" | yq '."app.kubernetes.io/component"' | tee /dev/stderr)
  [ "${actual}" = "rbac" ]
}

@test "CSIDriver/ClusterRole: rules are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq '.rules' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "4" ]

  actual=$(echo "$object" | yq '.[0].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "" ]
  actual=$(echo "$object" | yq '.[0].resources | join(",")' | tee /dev/stderr)
  [ "${actual}" = "pods,serviceaccounts,configmaps" ]
  actual=$(echo "$object" | yq '.[0].verbs | join(",")' | tee /dev/stderr)
  [ "${actual}" = "get,list,watch" ]

  actual=$(echo "$object" | yq '.[1].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "" ]
  actual=$(echo "$object" | yq '.[1].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "pods/status" ]
  actual=$(echo "$object" | yq '.[1].verbs[0]' | tee /dev/stderr)
  [ "${actual}" = "get" ]

  actual=$(echo "$object" | yq '.[2].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "" ]
  actual=$(echo "$object" | yq '.[2].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "events" ]
  actual=$(echo "$object" | yq '.[2].verbs | join(",")' | tee /dev/stderr)
  [ "${actual}" = "create,patch" ]

  actual=$(echo "$object" | yq '.[3].apiGroups[0]' | tee /dev/stderr)
  [ "${actual}" = "" ]
  actual=$(echo "$object" | yq '.[3].resources[0]' | tee /dev/stderr)
  [ "${actual}" = "serviceaccounts/token" ]
  actual=$(echo "$object" | yq '.[3].verbs | join(",")' | tee /dev/stderr)
  [ "${actual}" = "create,get,list,watch" ]
}

#--------------------------------------------------------------------
# cluster-role-binding tests

@test "CSIDriver/ClusterRoleBinding: metadata name is correct" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-binding.yaml \
    . | tee /dev/stderr |
    yq '.metadata.name' | tee /dev/stderr)

  [ "${object}" = "release-name-vault-secrets-operator-manager-rolebinding" ]
}

@test "CSIDriver/ClusterRoleBinding: labels are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-binding.yaml \
    . | tee /dev/stderr |
    yq '.metadata.labels' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "6" ]
  actual=$(echo "$object" | yq '."app.kubernetes.io/component"' | tee /dev/stderr)
  [ "${actual}" = "controller-manager" ]
}

@test "CSIDriver/ClusterRoleBinding: roleRef is correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-binding.yaml \
    . | tee /dev/stderr |
    yq '.roleRef' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '.kind' | tee /dev/stderr)
  [ "${actual}" = "ClusterRole" ]
  actual=$(echo "$object" | yq '.name' | tee /dev/stderr)
  [ "${actual}" = "release-name-vault-secrets-operator-manager-role" ]
}

@test "CSIDriver/ClusterRoleBinding: subjects are correctly set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/cluster-role-binding.yaml \
    . | tee /dev/stderr |
    yq '.subjects' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]

  actual=$(echo "$object" | yq '.[0].kind' | tee /dev/stderr)
  [ "${actual}" = "ServiceAccount" ]
  actual=$(echo "$object" | yq '.[0].name' | tee /dev/stderr)
  [ "${actual}" = "release-name-vault-secrets-operator-controller-manager" ]
  actual=$(echo "$object" | yq '.[0].namespace' | tee /dev/stderr)
  [ "${actual}" = "default" ]
}
