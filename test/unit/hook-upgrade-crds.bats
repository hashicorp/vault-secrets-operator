#!/usr/bin/env bats

#
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

#--------------------------------------------------------------------
@test "hookUpgradeCRDs: disabled" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        --set hooks.upgradeCRDs.enabled=false \
        . | tee /dev/stderr |
    yq '. | length' | tee /dev/stderr)
    [ "${actual}" = "0" ]
}

@test "hookUpgradeCRDs: enabled by default" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        . | tee /dev/stderr)

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local sa
    sa="$(echo "${object}" | yq 'select(di == 0)' | tee /dev/stderr)"
    [ "$(echo "${sa}" | \
      yq '.kind == "ServiceAccount"')" = "true" ]
    [ "$(echo "${sa}" | \
      yq '.metadata.annotations | length')" = "3" ]
    [ "$(echo "${sa}" | \
      yq '.metadata.annotations."helm.sh/hook" == "pre-upgrade"')" = "true" ]
    [ "$(echo "${sa}" | \
      yq '.metadata.annotations."helm.sh/hook-delete-policy" == "hook-succeeded,before-hook-creation"')" = "true" ]
    [ "$(echo "${sa}" | \
      yq '.metadata.annotations."helm.sh/hook-weight" == "1"')" = "true" ]

    local cr
    cr="$(echo "${object}" | yq 'select(di == 1)' | tee /dev/stderr)"
    [ "$(echo "${cr}" | yq '.kind == "ClusterRole"')" = "true" ]
    [ "$(echo "${cr}" | \
      yq '.metadata.annotations | length')" = "3" ]
    [ "$(echo "${cr}" | \
      yq '.metadata.annotations."helm.sh/hook" == "pre-upgrade"')" = "true" ]
    [ "$(echo "${cr}" | \
      yq '.metadata.annotations."helm.sh/hook-delete-policy" == "hook-succeeded,before-hook-creation"')" = "true" ]
    [ "$(echo "${cr}" | \
      yq '.metadata.annotations."helm.sh/hook-weight" == "2"')" = "true" ]

    local crb
    crb="$(echo "${object}" | yq 'select(di == 2)' | tee /dev/stderr)"
    [ "$(echo "${crb}" | yq '.kind == "ClusterRoleBinding"')" = "true" ]
    [ "$(echo "${crb}" | \
      yq '.metadata.annotations | length')" = "3" ]
    [ "$(echo "${crb}"  | \
      yq '.metadata.annotations."helm.sh/hook" == "pre-upgrade"')" = "true" ]
    [ "$(echo "${crb}"  | \
      yq '.metadata.annotations."helm.sh/hook-delete-policy" == "hook-succeeded,before-hook-creation"')" = "true" ]
    [ "$(echo "${crb}"  | \
      yq '.metadata.annotations."helm.sh/hook-weight" == "2"')" = "true" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}"  | \
      yq '.metadata.annotations | length')" = "3" ]
    [ "$(echo "${job}"  | \
      yq '.metadata.annotations."helm.sh/hook" == "pre-upgrade"')" = "true" ]
    [ "$(echo "${job}"  | \
      yq '.metadata.annotations."helm.sh/hook-delete-policy" == "hook-succeeded,before-hook-creation"')" = "true" ]
    [ "$(echo "${job}"  | \
      yq '.metadata.annotations."helm.sh/hook-weight" == "99"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.imagePullSecrets | length == 0)')" = "true" ]
}


@test "hookUpgradeCRDs: ClusterRole extended" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local cr
    cr="$(echo "${object}" | yq 'select(di == 1)')"
    [ "$(echo "${cr}" | yq '.kind == "ClusterRole"')" = "true" ]
    [ "$(echo "${cr}" | yq '(.rules | length) == 1')" = "true" ]
    [ "$(echo "${cr}" | yq '(.rules[0] | length) == 3')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].apiGroups[0] == "apiextensions.k8s.io"')" = "true" ]
    [ "$(echo "${cr}" | yq '(.rules[0].resources | length) == 1')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].resources[0] == "customresourcedefinitions"')" = "true" ]
    [ "$(echo "${cr}" | yq '(.rules[0].verbs | length) == 6')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[0] == "create"')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[1] == "delete"')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[2] == "get"')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[3] == "list"')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[4] == "patch"')" = "true" ]
    [ "$(echo "${cr}" | yq '.rules[0].verbs[5] == "update"')" = "true" ]
}

@test "hookUpgradeCRDs: Job extended" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.backoffLimit == 5')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers | length) == "1"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].command[0] == "/scripts/upgrade-crds"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].resources | length) == 2')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].env | length == 1)')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].imagePullPolicy == "IfNotPresent"')" = "true" ]
}

@test "hookUpgradeCRDs: Job extended with defaults" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.backoffLimit == 5')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers | length) == "1"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].command[0] == "/scripts/upgrade-crds"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].resources | length) == 2')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].env | length == 1)')" = "true" ]
}

@test "hookUpgradeCRDs: Job extended with custom values" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        -s templates/hook-upgrade-crds.yaml \
        --set hooks.upgradeCRDs.backoffLimit=10 \
        --set hooks.upgradeCRDs.executionTimeout='64s' \
        --set hooks.resources.limits.cpu='501m' \
        --set hooks.resources.limits.memory='129Mi' \
        --set hooks.resources.requests.cpu='11m' \
        --set hooks.resources.requests.memory='65Mi' \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | \
      yq '.spec.backoffLimit == 10')" = "true" ]
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers | length) == "1"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].command[0] == "/scripts/upgrade-crds"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].resources | length) == 2')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].resources.limits.cpu == "501m"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].resources.limits.memory == "129Mi"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].resources.requests.cpu == "11m"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].resources.requests.memory == "65Mi"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].env | length == 1)')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].env[0].name == "VSO_UPGRADE_CRDS_TIMEOUT"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].env[0].value == "64s"')" = "true" ]
}

@test "hookUpgradeCRDs: Job extended with imagePullSecrets" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        --set controller.imagePullSecrets[0].name='pullSecret1' \
        -s templates/hook-upgrade-crds.yaml \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.backoffLimit == 5')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers | length) == "1"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].command[0] == "/scripts/upgrade-crds"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].resources | length) == 2')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].env | length == 1)')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.imagePullSecrets | length == 1)')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.imagePullSecrets[0].name == "pullSecret1")')" = "true" ]
}

@test "hookUpgradeCRDs: Job extended with imagePullPolicy" {
    pushd "$(chart_dir)" > /dev/stderr
    local object
    object=$(helm template \
        --set controller.manager.image.pullPolicy='_Always_' \
        -s templates/hook-upgrade-crds.yaml \
        . )

    # assert that we have 4 documents using a base 0 index
    [ "$(echo "${object}" | yq '. | di' | tee /dev/stderr | tail -n1)" = "3" ]

    local job
    job="$(echo "${object}" | yq 'select(di == 3)' | tee /dev/stderr)"
    [ "$(echo "${job}" | yq '.kind == "Job"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.backoffLimit == 5')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers | length) == "1"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '.spec.template.spec.containers[0].command[0] == "/scripts/upgrade-crds"')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].resources | length) == 2')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].env | length == 1)')" = "true" ]
    [ "$(echo "${job}" | \
      yq '(.spec.template.spec.containers[0].imagePullPolicy == "_Always_")')" = "true" ]
}
