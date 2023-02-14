#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# enabled/disabled
  
@test "defaultConnection/CR: disabled by default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-vault-connection.yaml  \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "defaultConnection/CR: can be enabled" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-vault-connection.yaml  \
        --set 'defaultVaultConnection.enabled=true' \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
    [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# settings

@test "defaultConnection/CR: default settings for vault connection" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-vault-connection.yaml  \
        --set 'defaultVaultConnection.enabled=true' \
        . | tee /dev/stderr |
    yq '.' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
     [ "${actual}" = "release-name-vault-secrets-operator-default-connection" ]
    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]

    local actual=$(echo "$object" | yq '.spec.address' | tee /dev/stderr)
     [ "${actual}" = "http://vault.default.svc.cluster.local:8200" ]
    local actual=$(echo "$object" | yq '.spec.skipTLSVerify' | tee /dev/stderr)
     [ "${actual}" = "false" ]
}

@test "defaultConnection/CR: settings can be modified for vault connect" {
     cd `chart_dir`
     local object=$(helm template \
        -s templates/default-vault-connection.yaml  \
        --set 'defaultVaultConnection.enabled=true' \
        --set 'defaultVaultConnection.name=name-1' \
        --set 'defaultVaultConnection.namespace=tenant-1' \
        --set 'defaultVaultConnection.address=https://foo.com:8200' \
        --set 'defaultVaultConnection.skipTLSVerify=true' \
        --set 'defaultVaultConnection.caCertSecret=foo' \
        --set 'defaultVaultConnection.tlsServerName=foo.com' \
        --set 'defaultVaultConnection.headers=foo: bar' \
        . | tee /dev/stderr |
     yq '.' | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
     [ "${actual}" = "name-1" ]
    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "tenant-1" ]
    local actual=$(echo "$object" | yq '.spec.address' | tee /dev/stderr)
     [ "${actual}" = "https://foo.com:8200" ]
    local actual=$(echo "$object" | yq '.spec.skipTLSVerify' | tee /dev/stderr)
     [ "${actual}" = "true" ]
    local actual=$(echo "$object" | yq '.spec.caCertSecretRef' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
    local actual=$(echo "$object" | yq '.spec.tlsServerName' | tee /dev/stderr)
     [ "${actual}" = "foo.com" ]
    local actual=$(echo "$object" | yq '.spec.headers.foo' | tee /dev/stderr)
     [ "${actual}" = "bar" ]
}



