#!/usr/bin/env bats

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
