#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

# Script to install the mikefarah/yq tool to the bin directory.
# It ensures that only one copy of yq exists, and its version
# matches YQ_VERSION.
. ${0%/*}/.functions

set -e -o pipefail

YQ_VERSION="${YQ_VERSION-v4.43.1}"

pushd "$(git rev-parse --show-toplevel || echo .)" > /dev/null
dest_filename="yq-${YQ_VERSION}"
dest_file="bin/${dest_filename}"
if [ -f "${dest_file}" ]; then
  ln -sf "${dest_filename}" "${dest_file%/*}/yq"
  exit 0
fi

eval $(go env | egrep '^(GOOS|GOARCH)')
binary="yq_${GOOS}_${GOARCH}"
base_url="https://github.com/mikefarah/yq/releases/download/${YQ_VERSION}"

tempdir=$(mktemp -d)
function cleanup {
  rm -rf "${tempdir}"
}
trap cleanup EXIT SIGINT

# unfortunately the project has bizarre way of presenting checksums of their binaries, in this case
# we are implicitly trusting their released artifacts, as we would do for go install ...
pushd $tempdir > /dev/null
    getGH "${base_url}/${binary}" yq
    chmod +x yq
popd > /dev/null

rm -f "${dest_file%/*}"/yq*
mkdir -p bin/
mv "${tempdir}/yq" "${dest_file}"
ln -sf "${dest_filename}" "${dest_file%/*}/yq"

popd > /dev/null
