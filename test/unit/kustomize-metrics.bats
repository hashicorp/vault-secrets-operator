#!/usr/bin/env bats

# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

load _helpers

# The metrics endpoint is protected in-process by the manager, which only
# happens when it is started with the secure metrics flags. Overlays that patch
# the manager's args can silently drop them -- a strategic-merge patch on a
# scalar list replaces it rather than merging -- which leaves the binary on its
# insecure defaults while the Service still targets https:8443, so scrapes fail
# with no error at deploy time. Assert every overlay keeps the flags.

# manager_args builds the overlay and returns the manager container's args.
manager_args() {
  kustomize build "$(config_dir)/$1" | \
    yq 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "manager") | .args'
}

# manager_ports builds the overlay and returns the manager container's ports.
manager_ports() {
  kustomize build "$(config_dir)/$1" | \
    yq 'select(.kind == "Deployment") | .spec.template.spec.containers[] | select(.name == "manager") | .ports'
}

assert_secure_metrics() {
  local overlay="$1"
  local args
  args=$(manager_args "${overlay}" | tee /dev/stderr)

  local actual
  actual=$(echo "$args" | yq 'contains(["--metrics-secure=true"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]
  actual=$(echo "$args" | yq 'contains(["--metrics-bind-address=:8443"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]

  # The metrics Service targets the named port, so the manager must declare it.
  local ports
  ports=$(manager_ports "${overlay}" | tee /dev/stderr)
  actual=$(echo "$ports" | yq 'map(select(.name == "https" and .containerPort == 8443)) | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
}

@test "kustomize/default: metrics endpoint is secured" {
  assert_secure_metrics default
}

@test "kustomize/default-openshift: metrics endpoint is secured" {
  assert_secure_metrics default-openshift
}

@test "kustomize/persistence-unencrypted: metrics endpoint is secured" {
  assert_secure_metrics persistence-unencrypted
}

@test "kustomize/persistence-encrypted: metrics endpoint is secured" {
  assert_secure_metrics persistence-encrypted
}

@test "kustomize/persistence-encrypted-test: metrics endpoint is secured" {
  assert_secure_metrics persistence-encrypted-test
}

@test "kustomize/manifests: metrics endpoint is secured" {
  assert_secure_metrics manifests
}

@test "kustomize/persistence overlays: persistence args are appended, not replacing base args" {
  local args
  args=$(manager_args persistence-encrypted-test | tee /dev/stderr)

  local actual
  actual=$(echo "$args" | yq 'contains(["--client-cache-persistence-model=direct-encrypted"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]
  actual=$(echo "$args" | yq 'contains(["--zap-log-level=6"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]
  # Base args must survive alongside the appended ones.
  actual=$(echo "$args" | yq 'contains(["--leader-elect"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

@test "kustomize/default: no kube-rbac-proxy sidecar" {
  local names
  names=$(kustomize build "$(config_dir)/default" | \
    yq 'select(.kind == "Deployment") | .spec.template.spec.containers | map(.name)' | tee /dev/stderr)

  local actual
  actual=$(echo "$names" | yq 'contains(["kube-rbac-proxy"])' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}
