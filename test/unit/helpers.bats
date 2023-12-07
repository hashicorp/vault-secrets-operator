#!/usr/bin/env bats
# This file tests the helpers in _helpers.tpl.

load _helpers

#--------------------------------------------------------------------
# vso.chart.fullname
# These tests use test-runner.yaml to test the vso.chart.fullname helper
# since we need an existing template that calls the vso.chart.fullname helper.

@test "helper/vso.chart.fullname: defaults to release-name-vault-secrets-operator-test" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "release-name-vault-secrets-operator-test" ]
}

@test "helper/vso.chart.fullname: fullnameOverride overrides the name" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=override \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "override-test" ]
}

@test "helper/vso.chart.fullname: fullnameOverride is truncated to 63 chars" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz \
      . | tee /dev/stderr |
      yq -r '.metadata.annotations["fullNameOverride-test-annotation"]' | tee /dev/stderr)
  [ "${actual}" = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk-test" ]
}

@test "helper/vso.chart.fullname: fullnameOverride has trailing '-' trimmed" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=override- \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "override-test" ]
}

@test "helper/vso.resourceNameWithTruncation: resourceNameWithTruncation does not truncate short resource names" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=foo \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "foo-test" ]
}

@test "helper/vso.resourceNameWithTruncation: resourceNameWithTruncation truncates long resource names" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk" ]
}

#--------------------------------------------------------------------
# template namespace
#
# This test ensures that we set "namespace: " in every file. The exceptions are files with CRDs and clusterroles and
# clusterrolebindings.
#
# If this test fails, you're likely missing setting the namespace.

@test "helper/namespace: used everywhere" {
  cd `chart_dir`
  # Grep for files that don't have 'namespace: ' in them
  local actual=$(grep -L 'namespace: ' templates/*.yaml | grep -E -v 'crd|rbac|editor_role|viewer_role' | tee /dev/stderr )
  [ "${actual}" = '' ]
}

#--------------------------------------------------------------------
# component label
#
# This test ensures that we set "component" labels in every file.
# If this test fails, you're likely missing setting that label somewhere.
#

@test "helper/app.kubernetes.io/component label: used everywhere" {
  cd `chart_dir`
  # Grep for files that don't have 'component: ' in them
  local actual=$(grep -L 'app.kubernetes.io/component: ' templates/*.yaml | tee /dev/stderr )
  [ "${actual}" = '' ]
}
