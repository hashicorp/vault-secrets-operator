# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

ARG GO_VERSION=latest

# builder for the dev image
# -----------------------------------
FROM golang:$GO_VERSION as dev-builder

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

# Build
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o $BIN_NAME main.go

# dev image
# -----------------------------------
# Use distroless as minimal base image to package the operator binary
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot as dev
WORKDIR /
COPY --from=dev-builder /workspace/${BIN_NAME} .
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

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/
COPY LICENSE /licenses/copyright.txt

USER 65532:65532

ENTRYPOINT ["/bin/vault-secrets-operator"]

# ===================================
#
#   Set default target to 'dev'.
#
# ===================================
FROM dev
