# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

ARG GO_VERSION=latest

# builder for the dev image
# -----------------------------------
FROM golang:$GO_VERSION AS dev-builder

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
COPY common/ common/
COPY consts/ consts/
COPY controllers/ controllers/
COPY credentials/ credentials/
COPY helpers/ helpers/
COPY internal/ internal/
COPY template/ template/
COPY utils/ utils/
COPY vault/ vault/

# These flags gets redynamically computed on each `docker build` invocation, keep this under `go mod download` and friends
# so it doesn't unnecessarily bust the Docker cache.
ARG LD_FLAGS

# Build
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "$LD_FLAGS" -a -o $BIN_NAME main.go

# setup scripts directory needed for upgrading CRDs.
RUN mkdir scripts
COPY chart/crds scripts/crds
RUN ln -s ../$BIN_NAME scripts/upgrade-crds

# dev image
# -----------------------------------
# Use distroless as minimal base image to package the manager binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot AS dev
ENV BIN_NAME=vault-secrets-operator
WORKDIR /
COPY --from=dev-builder /workspace/$BIN_NAME /
COPY --from=dev-builder /workspace/scripts /scripts
USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# default release image
# -----------------------------------
FROM gcr.io/distroless/static:nonroot AS release-default

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
      org.opencontainers.image.licenses="BUSL-1.1" \
      summary="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets." \
      description="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets."

WORKDIR /

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /$BIN_NAME
COPY dist/$TARGETOS/$TARGETARCH/scripts /scripts

# May not be necessary, but copying the license to be consistent with the ubi image.
COPY LICENSE /licenses/copyright.txt
# Copy license to conform to HC IPS-002
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt


USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# ubi build image
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi-minimal:9.6 AS build-ubi
RUN microdnf --refresh --assumeyes upgrade ca-certificates

# ubi release image
# -----------------------------------
FROM registry.access.redhat.com/ubi9/ubi-micro:9.5 AS release-ubi

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
      org.opencontainers.image.licenses="BUSL-1.1" \
      summary="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets." \
      description="The Vault Secrets Operator (VSO) allows Pods to consume Vault secrets natively from Kubernetes Secrets."

WORKDIR /

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /$BIN_NAME
COPY dist/$TARGETOS/$TARGETARCH/scripts /scripts

# Copy license for Red Hat certification.
COPY LICENSE /licenses/copyright.txt
# Copy license to conform to HC IPS-002
COPY LICENSE /usr/share/doc/$PRODUCT_NAME/LICENSE.txt

COPY --from=build-ubi /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/

USER 65532:65532

ENTRYPOINT ["/vault-secrets-operator"]

# Duplicate ubi release image target for RedHat registry builds
# -------------------------------------------------------------
FROM release-ubi AS release-ubi-redhat

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
