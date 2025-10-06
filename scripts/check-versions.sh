#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

case "${VERSION}" in
  "")
    echo "VERSION variable must be set" >&2
    exit 1
    ;;
  *-dev)
    echo "version ${VERSION} is for a dev build, skipping version checks"
    exit 0
    ;;
esac

case "${KUBE_RBAC_PROXY_VERSION}" in
  "")
    echo "KUBE_RBAC_PROXY_VERSION variable must be set" >&2
    exit 1
    ;;
esac

ROOT_DIR="${0%/*}"
# update PATH to prefer scripts relative to this one e.g. yq
export PATH="${ROOT_DIR}:${ROOT_DIR}/../bin:${PATH}"

CHART_ROOT="${CHART_ROOT-$(readlink -f ${ROOT_DIR}/../chart)}"
KUSTOMIZE_ROOT="${KUSTOMIZE_ROOT-$(readlink -f ${ROOT_DIR}/../config)}"

_result=0
function checkVersion {
 local filename="${1}"
 local version="${2}"
 if ! [ -e ${filename} ]; then
   echo "${filename} file does not exist'" >&2
   _result=1
   return 1
 fi

 local doc="$(cat ${filename})"
 local actual
 local maybe_tag
 for query in "${@:3}"
 do
   echo "  * Expect version ${version} in ${filename} query='${query}'"
   actual="$(echo "${doc}" | yq "${query}")"
   # sometimes the value might be for an image+tag
   # e.g: gcr.io/kubebuilder/kube-rbac-proxy:v0.14.4,
   # in which case we only want the image's version/tag.
   maybe_tag="$(echo "${actual}" | awk -F: '/.+:.+/{print $NF}')"
   [ -n "${maybe_tag}" ] && actual="${maybe_tag}"
   if [ "${actual}" != "${version}" ]; then
        echo "yq-expr '${query}' does not match expected '${version}', actual='${actual}'" >&2
        _result=1
   fi
 done
}

echo "* Checking VSO images versions"
checkVersion "${CHART_ROOT}/Chart.yaml" "${VERSION}" .version .appVersion
checkVersion "${CHART_ROOT}/values.yaml" "${VERSION}" .controller.manager.image.tag
checkVersion "${KUSTOMIZE_ROOT}/manager/kustomization.yaml" "${VERSION}" \
  ".images.[] | select(.name == \"controller\") | .newTag"

# check RBAC proxy version/image
checkVersion "${CHART_ROOT}/values.yaml" "${KUBE_RBAC_PROXY_VERSION}" .controller.kubeRbacProxy.image.tag
checkVersion "${KUSTOMIZE_ROOT}/default/manager_auth_proxy_patch.yaml" \
  "${KUBE_RBAC_PROXY_VERSION}"  ".spec.template.spec.containers.[] | select(.name == \"kube-rbac-proxy\") | .image"

# check VSO-CSI related image versions
echo "* Checking VSO-CSI related image versions"
checkVersion "${CHART_ROOT}/values.yaml" "${VSO_CSI_DRIVER_VERSION}" .csi.driver.image.tag
checkVersion "${CHART_ROOT}/values.yaml" "${VSO_CSI_NODE_DRIVER_REGISTRAR_VERSION}" .csi.nodeDriverRegistrar.image.tag
checkVersion "${CHART_ROOT}/values.yaml" "${VSO_CSI_LIVENESS_PROBE_VERSION}" .csi.livenessProbe.image.tag

exit $_result
