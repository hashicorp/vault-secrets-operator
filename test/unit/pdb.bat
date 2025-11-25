#!/usr/bin/env bats

#
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

pdb_yaml() {
  helm template \
    --set "controller.podDisruptionBudget.enabled=true" \
    --set "controller.replicas=2" \
    "$@" \
    . | tee /dev/stderr |
    yq 'select(.kind == "PodDisruptionBudget" and .metadata.labels."app.kubernetes.io/component" == "controller-manager")' \
    | tee /dev/stderr
}

@test "controller/PodDisruptionBudget: defaults to minAvailable 1 when no constraints are set" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml)

  local actual

  # Should default to a safe minAvailable: 1
  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "1" ]

  # And must not set maxUnavailable at all
  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "controller/PodDisruptionBudget: uses only maxUnavailable when set and minAvailable is unset" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml \
    --set "controller.podDisruptionBudget.maxUnavailable=2")

  local actual

  # Should render only maxUnavailable: 2
  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "2" ]

  # minAvailable must not be set
  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "controller/PodDisruptionBudget: uses only minAvailable when set and maxUnavailable is unset" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml \
    --set "controller.podDisruptionBudget.minAvailable=2")

  local actual

  # Should render only minAvailable: 2
  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "2" ]

  # maxUnavailable must not be set
  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "controller/PodDisruptionBudget: when both set and minAvailable is zero, render only non-zero maxUnavailable" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml \
    --set "controller.podDisruptionBudget.maxUnavailable=3" \
    --set "controller.podDisruptionBudget.minAvailable=0")

  local actual

  # Only maxUnavailable should be emitted
  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "3" ]

  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "controller/PodDisruptionBudget: when both set and maxUnavailable is zero, render only non-zero minAvailable" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml \
    --set "controller.podDisruptionBudget.maxUnavailable=0" \
    --set "controller.podDisruptionBudget.minAvailable=3")

  local actual

  # Only minAvailable should be emitted
  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "3" ]

  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "controller/PodDisruptionBudget: fails when both maxUnavailable and minAvailable are non-zero" {
  cd `chart_dir`

  # Use Bats' `run` helper because we *expect* helm to fail here
  run helm template \
    --set "controller.podDisruptionBudget.enabled=true" \
    --set "controller.replicas=2" \
    --set "controller.podDisruptionBudget.maxUnavailable=1" \
    --set "controller.podDisruptionBudget.minAvailable=1" \
    .

  # Helm should fail due to both constraints being non-zero
  [ "$status" -ne 0 ]

  # Error message should mention both maxUnavailable and minAvailable
  echo "$output" | tee /dev/stderr | grep "maxUnavailable and minAvailable"
}

@test "controller/PodDisruptionBudget: supports percentage values for minAvailable" {
  cd `chart_dir`

  local output
  output=$(pdb_yaml \
    --set "controller.podDisruptionBudget.minAvailable=34%")

  local actual

  # Template should preserve the percentage as a string value
  actual=$(echo "$output" | yq '.spec.minAvailable' | tee /dev/stderr)
  [ "${actual}" = "34%" ]

  # And maxUnavailable should not be set in this case
  actual=$(echo "$output" | yq '.spec.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}
