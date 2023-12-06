#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#
# script to sync RBAC configuration from ./config/rbac to the Helm Chart.
#
# NOTE: this script only supports syncing the editor and viewer roles, the manager
# role etc, requires manual syncing
# requires yq (Go), not python-yq

set -e -o pipefail

ROOT_DIR="${0%/*}"
tempdir=$(mktemp -d)
function cleanup {
  rm -rf "${tempdir}"
}
trap cleanup EXIT SIGINT

CHART_ROOT="${CHART_ROOT-$(readlink -f ${ROOT_DIR}/../chart)}"

cp -a ${CHART_ROOT} ${tempdir}/.

CHART_TEMPLATE_ROOT="${CHART_ROOT?}/templates"
KUSTOMIZE_ROOT="${KUSTOMIZE_ROOT-$(readlink -f ${ROOT_DIR}/../config)}"
RBAC_ROOT="${KUSTOMIZE_ROOT?}/rbac"

function mungeIt {
  local infile="${1}"
  local outfile="${2}"
  if ! [ -f ${infile} ]; then
    echo "${infile} does not exist'" >&2
    return 1
  fi

  local output="$(cat ${infile})"
  local apiVersion="$(echo "${output}" | yq .apiVersion)"
  local kind="$(echo "${output}" | yq .kind)"
  local kindLower="$(echo "${kind}" | tr A-Z a-z)"
  local metadataName="$(echo "${output}" | yq .metadata.name)"
  local rules="$(echo "${output}"| yq .rules)"
  cat <<HERE > ${outfile}
{{- /*
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# auto generated by ${0##*/} -- do not edit
*/ -}}

apiVersion: ${apiVersion}
kind: ${kind}
metadata:
  name: {{ printf "%s-%s" (include "vso.chart.fullname" .) "${metadataName}" | trunc 63 | trimSuffix "-" }}
  labels:
    # allow for selecting on the canonical name
    vso.hashicorp.com/role-instance: ${metadataName}
  {{- include "vso.chart.labels" . | nindent 4 }}
rules:
${rules}
HERE
}

resultDir="${tempdir}/result"
mkdir -p "${resultDir}"
for f in ${RBAC_ROOT}/*_{editor,viewer}_role.yaml
do
   fn="${f##*/}"
   mungeIt "${f}" "${tempdir}/chart/templates/${fn}" || exit 1
   # validate it
   pushd "${tempdir}/chart" > /dev/null
   helm template -s templates/${fn} . > /dev/null || exit 1
   cp -a templates/${fn} ${resultDir}/.
   popd > /dev/null
done

rm -f ${CHART_TEMPLATE_ROOT}/*_{editor,viewer}_role.yaml
cp -a ${resultDir}/*.yaml ${CHART_TEMPLATE_ROOT}/.
