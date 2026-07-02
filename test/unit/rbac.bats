#!/usr/bin/env bats

#
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

# Templates that are gated solely on controller.rbac.enabled.
rbac_templates=(
    templates/role.yaml
    templates/cluster-role-binding.yaml
    templates/proxy-rbac.yaml
    templates/metrics-reader-rbac.yaml
    templates/leader-election-rbac.yaml
    templates/vaultauth_viewer_role.yaml
    templates/vaultauth_editor_role.yaml
)

#--------------------------------------------------------------------
# controller.rbac.enabled

@test "rbac/enabled: RBAC resources rendered by default" {
    cd "$(chart_dir)"
    for tpl in "${rbac_templates[@]}"; do
        local actual
        actual=$(helm template \
            -s "${tpl}" \
            . | tee /dev/stderr |
        yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
        [ "${actual}" = "true" ]
    done
}

@test "rbac/enabled: RBAC resources rendered when explicitly enabled" {
    cd "$(chart_dir)"
    for tpl in "${rbac_templates[@]}"; do
        local actual
        actual=$(helm template \
            -s "${tpl}" \
            --set 'controller.rbac.enabled=true' \
            . | tee /dev/stderr |
        yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
        [ "${actual}" = "true" ]
    done
}

@test "rbac/enabled: RBAC resources not rendered when disabled" {
    cd "$(chart_dir)"
    for tpl in "${rbac_templates[@]}"; do
        local actual
        actual=$(helm template \
            -s "${tpl}" \
            --set 'controller.rbac.enabled=false' \
            . | tee /dev/stderr |
        yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
        [ "${actual}" = "false" ]
    done
}

@test "rbac/enabled: aggregated roles not rendered when disabled" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        -s templates/clusterrole-aggregated-viewer.yaml \
        --set 'controller.rbac.enabled=false' \
        --set 'controller.rbac.clusterRoleAggregation.viewerRoles={*}' \
        . | tee /dev/stderr |
    yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
    [ "${actual}" = "false" ]

    actual=$(helm template \
        -s templates/clusterrole-aggregated-editor.yaml \
        --set 'controller.rbac.enabled=false' \
        --set 'controller.rbac.clusterRoleAggregation.editorRoles={*}' \
        . | tee /dev/stderr |
    yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "rbac/enabled: CSI RBAC resources not rendered when disabled" {
    cd "$(chart_dir)"
    local csi_rbac_templates=(
        templates/cluster-role-csi-driver.yaml
        templates/cluster-role-binding-csi-driver.yaml
        templates/clusterrole-aggregated-viewer-csi-driver.yaml
    )
    for tpl in "${csi_rbac_templates[@]}"; do
        local actual
        actual=$(helm template \
            -s "${tpl}" \
            --set 'csi.enabled=true' \
            --set 'controller.rbac.enabled=false' \
            . | tee /dev/stderr |
        yq ea '[select(.kind != null)] | length > 0' | tee /dev/stderr)
        [ "${actual}" = "false" ]
    done
}
