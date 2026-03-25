#!/usr/bin/env bats

#
# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

#--------------------------------------------------------------------
# viewer roles

@test "clusterRoleAggregatedViewer: default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/clusterrole-aggregated-viewer.yaml \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "clusterRoleAggregatedViewer: all" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-viewer.yaml \
        --debug \
        --set 'controller.rbac.clusterRoleAggregation.viewerRoles={*}' \
        . | tee /dev/stderr |
    yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[0].matchLabels["vso.hashicorp.com/aggregate-to-viewer"]' | tee /dev/stderr)
   [ "${actual}" = "true" ]
}

@test "clusterRoleAggregatedViewer: all user-facing" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-viewer.yaml \
        --set 'controller.rbac.clusterRoleAggregation.viewerRoles={*}' \
        --set 'controller.rbac.clusterRoleAggregation.userFacingRoles.view=true' \
        . | tee /dev/stderr)

   local selectors
   selectors=$(echo "$object" | yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   actual=$(echo "$selectors" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$selectors" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$selectors" | \
     yq '.[0].matchLabels["vso.hashicorp.com/aggregate-to-viewer"]' | tee /dev/stderr)
   [ "${actual}" = "true" ]

   local labels
   labels=$(echo "$object" | yq '.metadata.labels' | tee /dev/stderr)
   actual=$(echo "$labels" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "8" ]
   [ "$(echo "${labels}" | \
    yq '."rbac.authorization.k8s.io/aggregate-to-view" == "true"')" = "true" ]
}

@test "clusterRoleAggregatedViewer: subset" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-viewer.yaml \
        --debug \
        --set 'controller.rbac.clusterRoleAggregation.viewerRoles={HCPAuth,vaultAuth}' \
        . | tee /dev/stderr |
    yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "2" ]
   local actual=$(echo "$object" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[0].matchLabels["vso.hashicorp.com/role-instance"]' | tee /dev/stderr)
   [ "${actual}" = "hcpauth-viewer-role" ]
   local actual=$(echo "$object" | yq '.[1].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[1].matchLabels["vso.hashicorp.com/role-instance"]' | tee /dev/stderr)
   [ "${actual}" = "vaultauth-viewer-role" ]
}

#--------------------------------------------------------------------
# editor roles

@test "clusterRoleAggregatedEditor: default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/clusterrole-aggregated-editor.yaml \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "clusterRoleAggregatedEditor: all" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-editor.yaml \
        --set 'controller.rbac.clusterRoleAggregation.editorRoles={*}' \
        . | tee /dev/stderr |
    yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[0].matchLabels["vso.hashicorp.com/aggregate-to-editor"]' | tee /dev/stderr)
   [ "${actual}" = "true" ]
}

@test "clusterRoleAggregatedEditor: all user-facing" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-editor.yaml \
        --set 'controller.rbac.clusterRoleAggregation.editorRoles={*}' \
        --set 'controller.rbac.clusterRoleAggregation.userFacingRoles.edit=true' \
        . | tee /dev/stderr)

   local selectors
   selectors=$(echo "$object" | yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   actual=$(echo "$selectors" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$selectors" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$selectors" | \
     yq '.[0].matchLabels["vso.hashicorp.com/aggregate-to-editor"]' | tee /dev/stderr)
   [ "${actual}" = "true" ]

   local labels
   labels=$(echo "$object" | yq '.metadata.labels' | tee /dev/stderr)
   actual=$(echo "$labels" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "8" ]
   [ "$(echo "${labels}" | \
    yq '."rbac.authorization.k8s.io/aggregate-to-edit" == "true"')" = "true" ]
}

@test "clusterRoleAggregatedEditor: subset" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/clusterrole-aggregated-editor.yaml \
        --set 'controller.rbac.clusterRoleAggregation.editorRoles={HCPAuth,vaultAuth}' \
        . | tee /dev/stderr |
    yq '.aggregationRule.clusterRoleSelectors' | tee /dev/stderr)
   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "2" ]
   local actual=$(echo "$object" | yq '.[0].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[0].matchLabels["vso.hashicorp.com/role-instance"]' | tee /dev/stderr)
   [ "${actual}" = "hcpauth-editor-role" ]
   local actual=$(echo "$object" | yq '.[1].matchLabels | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   local actual=$(echo "$object" | \
     yq '.[1].matchLabels["vso.hashicorp.com/role-instance"]' | tee /dev/stderr)
   [ "${actual}" = "vaultauth-editor-role" ]
}
