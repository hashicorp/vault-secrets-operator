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
    yq '.' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
     [ "${actual}" = "release-name-vault-secrets-operator-default-auth" ]
    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]

    local actual=$(echo "$object" | yq '.spec.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    local actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    local actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "kubernetes" ]
    local actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
     [ "${actual}" = "kubernetes" ]
    local actual=$(echo "$object" | yq '.spec.kubernetes.role' | tee /dev/stderr)
     [ "${actual}" = "demo" ]
    local actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "default" ]
}

@test "defaultAuthMethod/CR: settings can be modified for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        --set 'defaultAuthMethod.vaultConnectionRef=foo' \
        --set 'defaultAuthMethod.name=name-1' \
        --set 'defaultAuthMethod.namespace=tenant-1' \
        --set 'defaultAuthMethod.vaultNamespace=tenant-2' \
        --set 'defaultAuthMethod.method=JWT' \
        --set 'defaultAuthMethod.mount=foo' \
        --set 'defaultAuthMethod.kubernetes.role=role-1' \
        --set 'defaultAuthMethod.kubernetes.serviceAccount=tenant-1' \
        --set 'defaultAuthMethod.kubernetes.tokenAudiences={vault,foo}' \
        --set 'defaultAuthMethod.headers=foo: bar' \
        --set 'defaultAuthMethod.params=foo: baz' \
        . | tee /dev/stderr |
    yq '.' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
     [ "${actual}" = "name-1" ]
    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-1" ]
    local actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-2" ]

    local actual=$(echo "$object" | yq '.spec.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    local actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "JWT" ]
    local actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    local actual=$(echo "$object" | yq '.spec.kubernetes.role' | tee /dev/stderr)
     [ "${actual}" = "role-1" ]
    local actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "tenant-1" ]
    local actual=$(echo "$object" | yq '.spec.kubernetes.audiences' | tee /dev/stderr)
     [ "${actual}" = '["vault", "foo"]' ]
    local actual=$(echo "$object" | yq '.spec.headers.foo' | tee /dev/stderr)
     [ "${actual}" = "bar" ]
    local actual=$(echo "$object" | yq '.spec.params.foo' | tee /dev/stderr)
     [ "${actual}" = "baz" ]
}

