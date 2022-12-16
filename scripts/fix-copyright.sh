#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

for y in $(find config/crd/bases config/rbac/role.yaml -name "*.yaml"); do
    OUTFILE=$(mktemp)

    cat ./hack/boilerplate.yaml.txt <(echo) $y > $OUTFILE
    mv $OUTFILE $y
done
