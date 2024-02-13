#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#
set -e -o pipefail

# Set the annotation `containerImage` in
# bundle/manifests/vault-secrets-operator.clusterserviceversion.yaml to the
# operator image in the deployment

BUILD_DIR="${BUILD_DIR:-build}"
HACK_DIR=$(dirname "$0")
CSV_FILE=${HACK_DIR}/../${BUILD_DIR}/bundle/manifests/vault-secrets-operator.clusterserviceversion.yaml
# bin/yq is installed by running 'make yq'
YQ=${HACK_DIR}/../bin/yq

IMAGE=$(cat ${CSV_FILE} | ${YQ} '.spec.install.spec.deployments.[] | select(.name == "vault-secrets-operator-controller-manager") | .spec.template.spec.containers.[] | select(.name == "manager") | .image')

cat ${CSV_FILE} | ${YQ} ".metadata.annotations.containerImage |= (\"${IMAGE}\")" > ${BUILD_DIR}/csv.yaml
mv ${BUILD_DIR}/csv.yaml ${CSV_FILE}
