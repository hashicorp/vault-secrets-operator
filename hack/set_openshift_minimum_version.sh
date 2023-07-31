#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


{
  echo ""
  echo "  # OpenShift minimum version"
  echo "  com.redhat.openshift.versions: v4.10"
} >> bundle/metadata/annotations.yaml
