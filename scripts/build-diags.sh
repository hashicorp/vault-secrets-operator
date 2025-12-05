#!/usr/bin/env bash
# Copyright IBM Corp. 2022, 2025
# SPDX-License-Identifier: BUSL-1.1

set -e

root="$(git rev-parse --show-toplevel || echo .)"
output_base_dir='build/docs/diags'

pushd ${root} > /dev/null
rm -rf ${output_base_dir}
mkdir -p ${output_base_dir}
docker run --rm -v .:/source plantuml/plantuml -o "/source/${output_base_dir}" '/source/docs/diags/*.puml'
echo -e "\nWrote images to ${root}/${output_base_dir}"
popd > /dev/null
