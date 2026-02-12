#!/usr/bin/env bash
# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1


{
  echo ""
  echo "  # OpenShift minimum version"
  echo "  com.redhat.openshift.versions: v4.10"
} >> build/bundle/metadata/annotations.yaml
