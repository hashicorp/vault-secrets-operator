#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

# Script for setting up the necessary Golang ldflags to set in the Operator's version.Version.

set -e

PACKAGE_PATH='github.com/hashicorp/vault-secrets-operator/internal/version'

export TZ=UTC
BUILD_DATE="$(date +%Y-%m-%dT%H:%M:%S%z)"
GIT_COMMIT="$(git rev-parse HEAD)"
if [[ -z $(git tag) ]]; then
    # if there are no tags then we use a place holder version
    # until the repo is finally tagged.
    GIT_VERSION='0.0.0-dev'
else
    # GIT_VERSION will either be the tag if it points to HEAD e.g v0.2.0, otherwise
    # the version will include the distance to the closest tag e.g. v0.2.0-1-g5bb74d4.
    # See the git-describe man page for more info.
    GIT_VERSION="$(git describe --tags --always --abbrev=7 $GIT_COMMIT)"
fi
GIT_TREE_STATE=dirty
[[ -z $(git status --porcelain) ]] && GIT_TREE_STATE=clean

eval $(echo -n "$GIT_VERSION" | awk '{sub(/^v/, "", $0); split($0,v,"."); printf("MAJOR=%s\nMINOR=%s\n", v[1], v[2])}')
[[ -z ${MAJOR} ]] && (echo "major version is empty, version=${GIT_VERSION}" >&2 ; exit 1)
[[ -z ${MINOR} ]] && (echo "minor version is empty, version=${GIT_VERSION}" >&2 ; exit 1)

eval $(go env)
flags=(
    -X ${PACKAGE_PATH}.Major=${MAJOR}
    -X ${PACKAGE_PATH}.Minor=${MINOR}
    -X ${PACKAGE_PATH}.GitVersion=${GIT_VERSION}
    -X ${PACKAGE_PATH}.GitCommit=${GIT_COMMIT}
    -X ${PACKAGE_PATH}.GitTreeState=${GIT_TREE_STATE}
    -X ${PACKAGE_PATH}.BuildDate=${BUILD_DATE}
    -X ${PACKAGE_PATH}.GoVersion=${GOVERSION}
    -X ${PACKAGE_PATH}.Compiler=gc
    -X ${PACKAGE_PATH}.Platform=${GOOS}/${GOARCH}
)

echo -n "${flags[@]}"
