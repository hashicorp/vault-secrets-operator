#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

output_dir="$(git rev-parse --show-toplevel || echo .)/build"
plantuml -o "${output_dir}" -progress ./docs/diags/*.puml
echo -e "\nWrote images to ${output_dir}"
