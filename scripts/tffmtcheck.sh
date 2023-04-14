#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

dir="${1:-.}"
terraform_bin=${TERRAFORM_BIN:-$(which terraform)}

echo "==> Checking that the TF code is properly formatted..."
if ! needs_update=$(${terraform_bin} fmt -recursive -check ${dir}) ; then
    cat << HERE >&2
terraform fmt needs to be run on following files:
  ${needs_update}
Run 'make fmttf' to reformat the code.
HERE
    exit 1
fi
