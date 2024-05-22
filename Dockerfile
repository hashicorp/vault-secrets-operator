# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

ARG GO_VERSION=latest

# builder for the dev image
# -----------------------------------
FROM golang:$GO_VERSION as dev-builder

ARG GOOS=linux
ARG GOARCH=amd64
ENV BIN_NAME=vault-secrets-operator
WORKDIR /workspace
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY api/ api/
COPY internal/ internal/
COPY controllers/ controllers/

# These flags gets redynamically computed on each `docker build` invocation, keep this under `go mod download` and friends
# so it doesn't unnecessarily bust the Docker cache.
ARG LD_FLAGS

# Build
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "$LD_FLAGS" -a -o $BIN_NAME main.go

# dev image
# -----------------------------------
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot as dev
WORKDIR /
COPY --from=dev-builder /workspace/$BIN_NAME /
USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# default release image
# -----------------------------------
FROM gcr.io/distroless/static:nonroot as release-default

ENV BIN_NAME=vault-secrets-operator
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL maintainer="Team Vault <vault@hashicorp.com>"
LABEL version=$PRODUCT_VERSION
LABEL revision=$PRODUCT_REVISION

WORKDIR /

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /
COPY LICENSE /licenses/copyright.txt

USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# ubi build image
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.4-949.1714662671 as build-ubi
RUN microdnf --refresh --assumeyes upgrade ca-certificates

# ubi release image
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi-micro:9.4-6 as release-ubi

ENV BIN_NAME=vault-secrets-operator
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
ARG PRODUCT_NAME=$BIN_NAME
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL name="Vault Secrets Operator" \
      maintainer="Team Vault <vault@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      revision=$PRODUCT_REVISION \
      summary="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets." \
      description="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets."

WORKDIR /

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /
COPY LICENSE /licenses/copyright.txt
COPY --from=build-ubi /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/

USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# Duplicate ubi release image target for RedHat registry builds
# -------------------------------------------------------------
FROM release-ubi as release-ubi-redhat

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
