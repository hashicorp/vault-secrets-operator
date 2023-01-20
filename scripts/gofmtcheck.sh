#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

dir="${1:-.}"
gofumpt_bin=${GOFUMPT_BIN:-$(which gofumpt)}

echo "==> Checking that code complies with gofumpt requirements..."
needs_update=$(find "${dir}" -type f -name '*.go' -print0 | xargs -0 ${gofumpt_bin} -l -extra)
if [[ -n ${needs_update} ]]; then
    cat << HERE >&2
gofumpt needs to be run on following files:
  ${needs_update}
Run 'make fmt' to reformat the code.
HERE
    exit 1
fi
