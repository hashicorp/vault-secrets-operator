#!/usr/bin/env bash
# Copyright (c) 2022 HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

output_dir="$(git rev-parse --show-toplevel || echo .)/build"
plantuml -o "${output_dir}" -progress ./docs/diags/*.puml
echo -e "\nWrote images to ${output_dir}"
