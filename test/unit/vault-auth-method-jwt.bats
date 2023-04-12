#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# enabled/disabled

@test "jwtAuthMethod/CR: disabled by default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/vault-auth-method-jwt.yaml \
        . | tee /dev/stderr |
        yq 'length > 0' | tee /dev/stderr)
   [ "${actual}" = "false" ]
}

@test "jwtAuthMethod/CR: can be enabled" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/vault-auth-method-jwt.yaml \
        --set 'jwtAuthMethod.enabled=true' \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# settings

@test "jwtAuthMethod/CR: default settings for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/vault-auth-method-jwt.yaml \
        --set 'jwtAuthMethod.enabled=true' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
     [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
     [ "${actual}" = "jwt" ]
    actual=$(echo "$object" | yq '.spec.jwt.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "default" ]
}

@test "jwtAuthMethod/CR: service account and token audiences settings can be modified for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/vault-auth-method-jwt.yaml \
        --set 'jwtAuthMethod.enabled=true' \
        --set 'jwtAuthMethod.namespace=tenant-2' \
        --set 'jwtAuthMethod.method=JWT' \
        --set 'jwtAuthMethod.mount=foo' \
        --set 'jwtAuthMethod.jwt.role=role-1' \
        --set 'jwtAuthMethod.jwt.serviceAccount=tenant-1' \
        --set 'jwtAuthMethod.jwt.tokenAudiences={vault,foo}' \
        --set 'jwtAuthMethod.headers=foo: bar' \
        --set 'jwtAuthMethod.params=foo: baz' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "JWT" ]
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

@test "jwtAuthMethod/CR: jwt secret settings can be modified for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/vault-auth-method-jwt.yaml \
        --set 'jwtAuthMethod.enabled=true' \
        --set 'jwtAuthMethod.namespace=tenant-2' \
        --set 'jwtAuthMethod.method=JWT' \
        --set 'jwtAuthMethod.mount=foo' \
        --set 'jwtAuthMethod.jwt.role=role-1' \
        --set 'jwtAuthMethod.jwt.secretName=secret-1' \
        --set 'jwtAuthMethod.jwt.secretKey=secret-key-1' \
        --set 'jwtAuthMethod.headers=foo: bar' \
        --set 'jwtAuthMethod.params=foo: baz' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-2" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "JWT" ]
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

