#!/usr/bin/env bash
# Copyright (c) 2022 HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DIR="${SCRIPT_DIR%/*}"

for y in $(find ${DIR}/config/crd/bases ${DIR}/config/rbac/role.yaml -name "*.yaml"); do
    OUTFILE=$(mktemp)

    cat ${DIR}/hack/boilerplate.yaml.txt <(echo) $y > $OUTFILE
    mv $OUTFILE $y
done
