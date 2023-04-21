#!/usr/bin/env bats

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
    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "default" ]
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
        --set 'defaultAuthMethod.headers=foo: bar' \
        --set 'defaultAuthMethod.params=foo: baz' \
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
        --set 'defaultAuthMethod.headers=foo: bar' \
        --set 'defaultAuthMethod.params=foo: baz' \
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
    actual=$(echo "$object" | yq '.spec.headers.foo' | tee /dev/stderr)
     [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params.foo' | tee /dev/stderr)
     [ "${actual}" = "baz" ]

    # secret related specs should not exist
    actual=$(echo "$object" | yq '.spec.jwt.secretName' | tee /dev/stderr)
     [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.jwt.secretKey' | tee /dev/stderr)
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
        --set 'defaultAuthMethod.jwt.secretName=secret-1' \
        --set 'defaultAuthMethod.jwt.secretKey=secret-key-1' \
        --set 'defaultAuthMethod.headers=foo: bar' \
        --set 'defaultAuthMethod.params=foo: baz' \
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
    actual=$(echo "$object" | yq '.spec.jwt.token.valueFrom.secretKeyRef.name' | tee /dev/stderr)
     [ "${actual}" = "secret-1" ]
    actual=$(echo "$object" | yq '.spec.jwt.token.valueFrom.secretKeyRef.key' | tee /dev/stderr)
     [ "${actual}" = "secret-key-1" ]
    actual=$(echo "$object" | yq '.spec.headers.foo' | tee /dev/stderr)
     [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params.foo' | tee /dev/stderr)
     [ "${actual}" = "baz" ]

    # serviceAccount and audiences specs should not exist
    actual=$(echo "$object" | yq '.spec.jwt.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = null ]
    actual=$(echo "$object" | yq '.spec.jwt.audiences' | tee /dev/stderr)
     [ "${actual}" = null ]
}

@test "defaultAuthMethod/CR: settings can be modified for approle auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.method=approle' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.approle.roleid=role-1' \
        --set 'defaultAuthMethod.approle.secretName=secret-1' \
        --set 'defaultAuthMethod.approle.secretKey=secret-key-1' \
        --set 'defaultAuthMethod.mount=foo' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "approle" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.approle.roleid' | tee /dev/stderr)
     [ "${actual}" = "role-1" ]
    actual=$(echo "$object" | yq '.spec.approle.secretKeyRef.name' | tee /dev/stderr)
     [ "${actual}" = "secret-1" ]
    actual=$(echo "$object" | yq '.spec.approle.secretKeyRef.key' | tee /dev/stderr)
     [ "${actual}" = "secret-key-1" ]
}
