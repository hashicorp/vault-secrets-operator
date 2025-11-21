# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

schema = 1
artifacts {
  zip = [
    "vault-secrets-operator_${version}_linux_amd64.zip",
    "vault-secrets-operator_${version}_linux_arm64.zip",
    "vault-secrets-operator_${version}_linux_s390x.zip",
  ]
  container = [
    "vault-secrets-operator_release-default_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-secrets-operator_release-default_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-secrets-operator_release-default_linux_s390x_${version}_${commit_sha}.docker.tar",
    "vault-secrets-operator_release-ubi_linux_amd64_${version}_${commit_sha}.docker.redhat.tar",
    "vault-secrets-operator_release-ubi_linux_arm64_${version}_${commit_sha}.docker.redhat.tar",
    "vault-secrets-operator_release-ubi_linux_s390x_${version}_${commit_sha}.docker.redhat.tar",
    "vault-secrets-operator_release-ubi_linux_amd64_${version}_${commit_sha}.docker.tar",
    "vault-secrets-operator_release-ubi_linux_arm64_${version}_${commit_sha}.docker.tar",
    "vault-secrets-operator_release-ubi_linux_s390x_${version}_${commit_sha}.docker.tar",
  ]
}
