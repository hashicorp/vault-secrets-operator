#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Script to install the operator-sdk CLI tool to the bin directory.
# It ensures that only one copy of operator-sdk exists, and its version
# matches OPERATOR_SDK_VERSION.
. ${0%/*}/.functions

set -e -o pipefail

OPERATOR_SDK_VERSION="${OPERATOR_SDK_VERSION-1.33.0}"

pushd "$(git rev-parse --show-toplevel || echo .)" > /dev/null
dest_filename="operator-sdk-${OPERATOR_SDK_VERSION}"
dest_file="bin/${dest_filename}"
if [ -f "${dest_file}" ]; then
  ln -sf "${dest_filename}" "${dest_file%/*}/operator-sdk"
  exit 0
fi

eval "$(go env | grep -E '^(GOOS|GOARCH)')"
binary="operator-sdk_${GOOS}_${GOARCH}"
base_url="https://github.com/operator-framework/operator-sdk/releases/download/v${OPERATOR_SDK_VERSION}"
tempdir=$(mktemp -d)

function cleanup {
  rm -rf "${tempdir}"
}
trap cleanup EXIT SIGINT

pushd $tempdir > /dev/null
    getGH "${base_url}/checksums.txt"
    getGH "${base_url}/${binary}" "${binary}"
    grep "${binary}" checksums.txt | sha256sum -c -
popd > /dev/null

rm -f "${dest_file%/*}"/operator-sdk*
mkdir -p bin/
mv "${tempdir}/operator-sdk_${GOOS}_${GOARCH}" "${dest_file}"
chmod +x "${dest_file}"
ln -sf "${dest_filename}" "${dest_file%/*}/operator-sdk"

popd > /dev/null
