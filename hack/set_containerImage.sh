#!/usr/bin/env bash -e
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Set the annotation `containerImage` in
# bundle/manifests/vault-secrets-operator.clusterserviceversion.yaml to the
# operator image in the deployment

HACK_DIR=$(dirname "$0")
CSV_FILE=${HACK_DIR}/../bundle/manifests/vault-secrets-operator.clusterserviceversion.yaml
YQ=${HACK_DIR}/../scripts/yq

IMAGE=$(cat ${CSV_FILE} | ${YQ} '.spec.install.spec.deployments.[] | select(.name == "vault-secrets-operator-controller-manager") | .spec.template.spec.containers.[] | select(.name == "manager") | .image')

cat ${CSV_FILE} | ${YQ} ".metadata.annotations.containerImage |= (\"${IMAGE}\")" > ${TMPDIR}/csv.yaml
cp ${TMPDIR}/csv.yaml ${CSV_FILE}
