#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

if [ -z "${VERSION}" ]; then
  echo "VERSION variable must be set" >&2
  exit 1
fi

if [ "${VERSION}" == "0.0.0-dev" ]; then
  echo "dev build, skipping version checks"
  exit 0
fi

ROOT_DIR="${0%/*}"
# update PATH to prefer scripts relative to this one e.g. yq
export PATH="${ROOT_DIR}:${PATH}"

CHART_ROOT="${CHART_ROOT-$(readlink -f ${0%/*}/../chart)}"
KUSTOMIZE_ROOT="${KUSTOMIZE_ROOT-$(readlink -f ${0%/*}/../config)}"

_result=0
function checkVersion {
 local filename="${1}"
 if ! [ -e ${filename} ]; then
   echo "${filename} file does not exist'" >&2
   _result=1
   return 1
 fi

 local doc="$(cat ${filename})"
 echo "* Checking version(s) in ${filename}"
 for query in "${@:2}"
 do
   actual="$(echo "${doc}" | yq "${query}")"
   if [ "${actual}" != "${VERSION}" ]; then
        echo "yq-expr '${query}' does not match expected '${VERSION}', actual='${actual}'" >&2
        _result=1
   fi
 done
}

checkVersion "${CHART_ROOT}/Chart.yaml" .version .appVersion
checkVersion "${CHART_ROOT}/values.yaml" .controller.manager.image.tag
checkVersion "${KUSTOMIZE_ROOT}/manager/kustomization.yaml" ".images.[] | select(.name == \"controller\") | .newTag"

exit $_result
