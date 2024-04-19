#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Script to install the hashicorp/copywrite tool to the bin directory.
# It ensures that only one copy of copywrite exists, and its version
# matches COPYWRITE_VERSION.
. ${0%/*}/.functions

set -e -o pipefail

COPYWRITE_VERSION="${COPYWRITE_VERSION-0.16.3}"

pushd "$(git rev-parse --show-toplevel || echo .)" > /dev/null
dest_filename="copywrite-${COPYWRITE_VERSION}"
dest_file="bin/${dest_filename}"
if [ -f "${dest_file}" ]; then
  ln -sf "${dest_filename}" "${dest_file%/*}/copywrite"
  exit 0
fi

eval $(go env | egrep '^(GOOS|GOARCH)')
if [ "$GOARCH" == 'amd64' ]; then
  GOARCH='x86_64'
fi

archive_file="copywrite_${COPYWRITE_VERSION}_${GOOS}_${GOARCH}.tar.gz"
base_url="https://github.com/hashicorp/copywrite/releases/download/v${COPYWRITE_VERSION}"
tempdir=$(mktemp -d)

function cleanup {
  rm -rf "${tempdir}"
}
trap cleanup EXIT SIGINT

pushd $tempdir > /dev/null
    getGH "${base_url}/SHA256SUMS"
    getGH "${base_url}/${archive_file}" "${archive_file}"
    grep "${archive_file}" SHA256SUMS | sha256sum -c -
    tar -xzf "${archive_file}" copywrite
popd > /dev/null

rm -f "${dest_file%/*}"/copywrite*
mkdir -p bin/
mv "${tempdir}/copywrite" "${dest_file}"
ln -sf "${dest_filename}" "${dest_file%/*}/copywrite"

popd > /dev/null
