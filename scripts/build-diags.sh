#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

output_dir="$(git rev-parse --show-toplevel || echo .)/build/docs/diags"
rm -rf ${output_dir}
mkdir -p ${output_dir}
plantuml -o "${output_dir}" -progress ./docs/diags/*.puml
echo -e "\nWrote images to ${output_dir}"
