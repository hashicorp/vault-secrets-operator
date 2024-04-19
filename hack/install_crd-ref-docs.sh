#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Script to install the crd-ref-docs tool to the bin directory.
# It ensures that only one copy of crd-ref-docs exists, and its version
# matches CRD_REF_DOCS_VERSION.
set -e -o pipefail

CRD_REF_DOCS_VERSION="${CRD_REF_DOCS_VERSION-v0.0.12}"

pushd "$(git rev-parse --show-toplevel || echo .)" > /dev/null
dest_filename="crd-ref-docs-${CRD_REF_DOCS_VERSION}"
dest_file="bin/${dest_filename}"
if [ -f "${dest_file}" ]; then
  ln -sf "${dest_filename}" "${dest_file%/*}/crd-ref-docs"
  exit 0
fi

tempdir=$(mktemp -d)

function cleanup {
  rm -rf "${tempdir}"
}
trap cleanup EXIT SIGINT

GOBIN="$tempdir" go install github.com/elastic/crd-ref-docs@${CRD_REF_DOCS_VERSION}
rm -f "${dest_file%/*}"/crd-ref-docs*
mkdir -p bin/
mv "${tempdir}/crd-ref-docs" "${dest_file}"
ln -sf "${dest_filename}" "${dest_file%/*}/crd-ref-docs"
