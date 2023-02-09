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
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    local actual=$(echo "$object" | yq '.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    local actual=$(echo "$object" | yq '.method' | tee /dev/stderr)
     [ "${actual}" = "kubernetes" ]
    local actual=$(echo "$object" | yq '.mount' | tee /dev/stderr)
     [ "${actual}" = "kubernetes" ]
    local actual=$(echo "$object" | yq '.kubernetes.role' | tee /dev/stderr)
     [ "${actual}" = "demo" ]
    local actual=$(echo "$object" | yq '.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "default" ]
}

@test "defaultAuthMethod/CR: settings can be modified for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultConnectionRef=foo' \
        --set 'defaultAuthMethod.namespace=tenant-1' \
        --set 'defaultAuthMethod.method=JWT' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.kubernetes.role=role-1' \
        --set 'defaultAuthMethod.kubernetes.serviceAccount=tenant-1' \
        --set 'defaultAuthMethod.headers=foo: bar' \
        --set 'defaultAuthMethod.params=foo: baz' \
        . | tee /dev/stderr |
    yq '.spec' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    local actual=$(echo "$object" | yq '.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-1" ]
    local actual=$(echo "$object" | yq '.method' | tee /dev/stderr)
     [ "${actual}" = "JWT" ]
    local actual=$(echo "$object" | yq '.mount' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    local actual=$(echo "$object" | yq '.kubernetes.role' | tee /dev/stderr)
     [ "${actual}" = "role-1" ]
    local actual=$(echo "$object" | yq '.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "tenant-1" ]
    local actual=$(echo "$object" | yq '.headers.foo' | tee /dev/stderr)
     [ "${actual}" = "bar" ]
    local actual=$(echo "$object" | yq '.params.foo' | tee /dev/stderr)
     [ "${actual}" = "baz" ]
}





