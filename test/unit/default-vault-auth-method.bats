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
    # storageEncryption is disabled by default
    actual=$(echo "$object" | yq '.metadata.storageEncryption.keyName | length > 0' | tee /dev/stderr)
     [ "${actual}" = "false" ]
    actual=$(echo "$object" | yq '.metadata.storageEncryption.mount | length > 0' | tee /dev/stderr)
     [ "${actual}" = "false" ]
}

@test "defaultAuthMethod/CR: settings can be modified for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=JWT' \
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
     [ "${actual}" = "JWT" ]
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

@test "defaultAuthMethod/CR: storageEncyption can be configured" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.namespace=tenant-2' \
        --set 'defaultAuthMethod.method=JWT' \
        --set 'defaultAuthMethod.storageEncryption.enabled=true' \
        --set 'defaultAuthMethod.storageEncryption.keyName=foo' \
        --set 'defaultAuthMethod.storageEncryption.mount=foo/bar/baz' \
        . | tee /dev/stderr)

    actual=$(echo "$object" | yq '.spec.storageEncryption.keyName' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    actual=$(echo "$object" | yq '.spec.storageEncryption.mount' | tee /dev/stderr)
     [ "${actual}" = "foo/bar/baz" ]
}

