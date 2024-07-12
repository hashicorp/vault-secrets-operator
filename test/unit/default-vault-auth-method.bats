#!/usr/bin/env bats

#
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

#--------------------------------------------------------------------
# enabled/disabled

@test "defaultAuthMethod/CR: disabled by default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        . | tee /dev/stderr |
        yq 'length > 0' | tee /dev/stderr)
   [ "${actual}" = "false" ]
}

@test "defaultAuthMethod/CR: can be enabled" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# settings

@test "defaultAuthMethod/CR: default settings for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.allowedNamespaces' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "default" ]
}

@test "defaultAuthMethod/CR: allowedNamespaces" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.allowedNamespaces={tenant-1,tenant-2}' \
        --set 'defaultAuthMethod.enabled=true' \
        . | tee /dev/stderr)

    local allowed=$(echo "${object}" | yq '.spec.allowedNamespaces')
    actual=$(echo "${allowed}" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '2' ]
    actual=$(echo "${allowed}" | yq '.[0]' | tee /dev/stderr)
    [ "${actual}" = 'tenant-1' ]
    actual=$(echo "${allowed}" | yq '.[1]' | tee /dev/stderr)
    [ "${actual}" = 'tenant-2' ]
}

@test "defaultAuthMethod/CR: settings can be modified for kubernetes auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.kubernetes.role=role-1' \
        --set 'defaultAuthMethod.kubernetes.serviceAccount=tenant-1' \
        --set 'defaultAuthMethod.kubernetes.tokenAudiences={vault,foo}' \
        --set 'defaultAuthMethod.headers.foo=bar' \
        --set 'defaultAuthMethod.params.foo=baz' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "tenant-1" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.audiences' | tee /dev/stderr)
    [ "${actual}" = '["vault", "foo"]' ]
    actual=$(echo "$object" | yq '.spec.headers.foo' | tee /dev/stderr)
    [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params.foo' | tee /dev/stderr)
    [ "${actual}" = "baz" ]
}

@test "defaultAuthMethod/CR: default settings for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.method=jwt' \
        --set 'defaultAuthMethod.mount=jwt' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.jwt.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "default" ]

    # secret related specs should not exist
    actual=$(echo "$object" | yq '.spec.jwt.secretName' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.jwt.secretKey' | tee /dev/stderr)
    [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: service account and token audiences settings can be modified for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=jwt' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.jwt.role=role-1' \
        --set 'defaultAuthMethod.jwt.serviceAccount=tenant-1' \
        --set 'defaultAuthMethod.jwt.tokenAudiences={vault,foo}' \
        --set 'defaultAuthMethod.headers.foo=bar' \
        --set 'defaultAuthMethod.params.foo=baz' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.jwt.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.jwt.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "tenant-1" ]
    actual=$(echo "$object" | yq '.spec.jwt.audiences' | tee /dev/stderr)
    [ "${actual}" = '["vault", "foo"]' ]
    actual=$(echo "$object" | yq '.spec.headers | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.headers."foo"' | tee /dev/stderr)
    [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.params."foo"' | tee /dev/stderr)
    [ "${actual}" = "baz" ]

    # secret related specs should not exist
    actual=$(echo "$object" | yq '.spec.jwt.secretRef' | tee /dev/stderr)
    [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: token secret settings can be modified for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=jwt' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.jwt.role=role-1' \
        --set 'defaultAuthMethod.jwt.secretRef=secret-1' \
        --set 'defaultAuthMethod.headers.foo=bar' \
        --set 'defaultAuthMethod.params.foo=baz' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.jwt.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.jwt.secretRef' | tee /dev/stderr)
    [ "${actual}" = "secret-1" ]
    actual=$(echo "$object" | yq '.spec.headers | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.headers."foo"' | tee /dev/stderr)
    [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.params."foo"' | tee /dev/stderr)
    [ "${actual}" = "baz" ]

    # serviceAccount and audiences specs should not exist
    actual=$(echo "$object" | yq '.spec.jwt.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.jwt.audiences' | tee /dev/stderr)
    [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: settings can be modified for appRole auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.method=appRole' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.appRole.roleId=role-1' \
        --set 'defaultAuthMethod.appRole.secretRef=secret-1' \
        --set 'defaultAuthMethod.mount=foo' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "appRole" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.appRole.roleId' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.appRole.secretRef' | tee /dev/stderr)
    [ "${actual}" = "secret-1" ]
}

@test "defaultAuthMethod/CR: settings can be modified for aws auth method - minimum" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=aws' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.aws.role=role-1' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "aws" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.aws.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]

    # the rest should not be set
    actual=$(echo "$object" | yq '.spec.aws.region' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.headerValue' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.sessionName' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.stsEndpoint' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.iamEndpoint' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.secretRef' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.aws.irsaServiceAccount' | tee /dev/stderr)
    [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: settings can be modified for aws auth method - everything" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=aws' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.aws.role=role-1' \
        --set 'defaultAuthMethod.aws.region=us-test-2' \
        --set 'defaultAuthMethod.aws.headerValue=test-value' \
        --set 'defaultAuthMethod.aws.sessionName=new-session' \
        --set 'defaultAuthMethod.aws.stsEndpoint=www.sts' \
        --set 'defaultAuthMethod.aws.iamEndpoint=www.iam' \
        --set 'defaultAuthMethod.aws.secretRef=aws-creds' \
        --set 'defaultAuthMethod.aws.irsaServiceAccount=iam-irsa-acct' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "aws" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.aws.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.aws.region' | tee /dev/stderr)
    [ "${actual}" = "us-test-2" ]
    actual=$(echo "$object" | yq '.spec.aws.headerValue' | tee /dev/stderr)
    [ "${actual}" = "test-value" ]
    actual=$(echo "$object" | yq '.spec.aws.sessionName' | tee /dev/stderr)
    [ "${actual}" = "new-session" ]
    actual=$(echo "$object" | yq '.spec.aws.stsEndpoint' | tee /dev/stderr)
    [ "${actual}" = "www.sts" ]
    actual=$(echo "$object" | yq '.spec.aws.iamEndpoint' | tee /dev/stderr)
    [ "${actual}" = "www.iam" ]
    actual=$(echo "$object" | yq '.spec.aws.secretRef' | tee /dev/stderr)
    [ "${actual}" = "aws-creds" ]
    actual=$(echo "$object" | yq '.spec.aws.irsaServiceAccount' | tee /dev/stderr)
    [ "${actual}" = "iam-irsa-acct" ]
}

@test "defaultAuthMethod/CR: settings can be modified for gcp auth method - minimum" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=gcp' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.gcp.role=role-1' \
        --set 'defaultAuthMethod.gcp.workloadIdentityServiceAccount=my-identity-sa' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "gcp" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.gcp.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.gcp.workloadIdentityServiceAccount' | tee /dev/stderr)
    [ "${actual}" = "my-identity-sa" ]

    # the rest should not be set
    actual=$(echo "$object" | yq '.spec.gcp.region' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.gcp.clusterName' | tee /dev/stderr)
    [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.gcp.projectID' | tee /dev/stderr)
    [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: settings can be modified for gcp auth method - everything" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=gcp' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.gcp.role=role-1' \
        --set 'defaultAuthMethod.gcp.workloadIdentityServiceAccount=my-identity-sa' \
        --set 'defaultAuthMethod.gcp.region=us-test-2' \
        --set 'defaultAuthMethod.gcp.clusterName=test-cluster' \
        --set 'defaultAuthMethod.gcp.projectID=my-project' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
    [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "gcp" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.gcp.role' | tee /dev/stderr)
    [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.gcp.workloadIdentityServiceAccount' | tee /dev/stderr)
    [ "${actual}" = "my-identity-sa" ]
    actual=$(echo "$object" | yq '.spec.gcp.region' | tee /dev/stderr)
    [ "${actual}" = "us-test-2" ]
    actual=$(echo "$object" | yq '.spec.gcp.clusterName' | tee /dev/stderr)
    [ "${actual}" = "test-cluster" ]
    actual=$(echo "$object" | yq '.spec.gcp.projectID' | tee /dev/stderr)
    [ "${actual}" = "my-project" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/default" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '. | has("vaultAuthGlobalRef")')" = "false" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/enabled" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef | has("allowDefault")')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.params')" = "none" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.headers')" = "none" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/defaults/empty-params" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.mergeStrategy.params=' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef | has("allowDefault")')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy | has("params")')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.headers')" = "none" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/mergeStrategy/empty-headers" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.mergeStrategy.headers=' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef | has("allowDefault")')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.params')" = "none" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy | has("headers")')" = "false" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/allowDefault=true" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.allowDefault=true' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.allowDefault')" = "true" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/allowDefault=false" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.allowDefault=false' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.allowDefault')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
}

@test "defaultAuthMethod/CR: with vaultAuthGlobalRef/mergeStrategy/params=union-headers=replace" {
    cd "$(chart_dir)"
    local actual
    actual=$(helm template \
        --debug \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.enabled=true' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.name=foo' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.namespace=baz' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.allowDefault=false' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.mergeStrategy.params=union' \
        --set 'defaultAuthMethod.vaultAuthGlobalRef.mergeStrategy.headers=replace' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.allowDefault')" = "false" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.name')" = "foo" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.namespace')" = "baz" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.params')" = "union" ]
    [ "$(echo "$actual" | yq '.vaultAuthGlobalRef.mergeStrategy.headers')" = "replace" ]
}
