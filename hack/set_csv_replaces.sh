#!/usr/bin/env bash
# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1
set -e -o pipefail

# Set the `spec.replaces` parameter in the ClusterServiceVersion (CSV) to the
# previous version, so that the graph of CSVs is built correctly and previous
# versions show up in OperatorHub.
#
# https://access.redhat.com/documentation/en-us/openshift_container_platform/4.2/html/operators/understanding-the-operator-lifecycle-manager-olm
#
# Override the `replaces` version by setting PREVIOUS_VERSION to "vX.Y.Z"

if [ -z "${PREVIOUS_VERSION}" ]; then
  PREVIOUS_GIT_TAG=$(git describe --abbrev=0 --tags "$(git rev-list --tags --skip=1 --max-count=1)")
  PREVIOUS_VERSION="${PREVIOUS_GIT_TAG}"
fi

CSV="build/bundle/manifests/vault-secrets-operator.clusterserviceversion.yaml"

CHECK="$(grep 'replaces:' ${CSV} || true)"
if [ -n "${CHECK}" ]; then
  echo "replaces already set in ${CSV}:"
  echo "${CHECK}"
  exit 0
fi

if [ -z "${PREVIOUS_VERSION}" ]; then
  echo "unable to determine PREVIOUS_VERSION"
  exit 1
fi

echo "  replaces: vault-secrets-operator.${PREVIOUS_VERSION?}" >> ${CSV}
