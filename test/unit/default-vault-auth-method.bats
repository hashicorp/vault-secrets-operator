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
        . | yq 'select(documentIndex == 0) | .kind' | tee /dev/stderr)
  [ "${actual}" = "VaultAuth" ]
}

#--------------------------------------------------------------------
# settings

@test "defaultAuthMethod/CR: default settings for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-auth-method.yaml  \
        --set 'defaultAuthMethod.enabled=true' \
        . | yq 'select(documentIndex == 0)' | tee /dev/stderr)

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
        . | yq 'select(documentIndex == 0)' | tee /dev/stderr)

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

