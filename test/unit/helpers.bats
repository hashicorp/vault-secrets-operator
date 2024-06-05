#!/usr/bin/env bats
# This file tests the helpers in _helpers.tpl.

load _helpers

#--------------------------------------------------------------------
# chart.fullname
# These tests use test-runner.yaml to test the chart.fullname helper
# since we need an existing template that calls the chart.fullname helper.

@test "helper/chart.fullname: defaults to release-name-vault-secrets-operator-test" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "release-name-vault-secrets-operator-test" ]
}

@test "helper/chart.fullname: fullnameOverride overrides the name" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=override \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "override-test" ]
}

@test "helper/chart.fullname: fullnameOverride is truncated to 63 chars" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk-test" ]
}

@test "helper/chart.fullname: fullnameOverride has trailing '-' trimmed" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/tests/test-runner.yaml \
      --set fullnameOverride=override- \
      . | tee /dev/stderr |
      yq -r '.metadata.name' | tee /dev/stderr)
  [ "${actual}" = "override-test" ]
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
  local actual=$(grep -L 'namespace: ' templates/*.yaml | grep -E -v 'crd|rbac|editor_role|viewer_role|role.yaml|clusterrole' | tee /dev/stderr )
  [ "${actual}" = '' ]
}

#--------------------------------------------------------------------
# component label
#
@test "helper/app.kubernetes.io/component label: included in all resources" {
  cd `chart_dir`
  local actual=$(helm template . |  \
   yq '({"match": .metadata.labels | has("app.kubernetes.io/component"), "doc": document_index, "name": .metadata.name, "kind": .kind, "apiVersion": .apiVersion})' \
     | tee /dev/stderr | grep -c 'match: false')
  [ "${actual}" = '0' ]
}
