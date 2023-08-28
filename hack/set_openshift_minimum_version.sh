#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1


{
  echo ""
  echo "  # OpenShift minimum version"
  echo "  com.redhat.openshift.versions: v4.10"
} >> build/bundle/metadata/annotations.yaml
