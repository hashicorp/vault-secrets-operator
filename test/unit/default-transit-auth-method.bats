#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# enabled/disabled

@test "defaultTransitAuthMethod/CR: disabled by default" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        . | tee /dev/stderr |
        yq 'length > 0' | tee /dev/stderr)
   [ "${actual}" = "false" ]
}

@test "defaultTransitAuthMethod/CR: can be enabled" {
    cd `chart_dir`
    local actual=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        . | tee /dev/stderr |
    yq 'length > 0' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# settings

@test "defaultTransitAuthMethod/CR: kubernetes default serviceaccount uses operator sa as a default" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        . | tee /dev/stderr)

    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "release-name-vault-secrets-operator-controller-manager" ]
}

@test "defaultTransitAuthMethod/CR: default vaultConnectionRef is used by default" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.spec.vaultConnectionRef' | tee /dev/stderr)
    [ "${actual}" = "default" ]
}

@test "defaultTransitAuthMethod/CR: default settings for auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
    [ "${actual}" = "release-name-vault-secrets-operator-default-transit-auth" ]
    actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
    [ "${actual}" = "default" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
    [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
    [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
    [ "${actual}" = "release-name-vault-secrets-operator-controller-manager" ]
}

@test "defaultTransitAuthMethod/CR: settings can be modified for kubernetes auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.namespace=tenant-2' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo' \
        --set 'controller.manager.clientCache.storageEncryption.kubernetes.role=role-1' \
        --set 'controller.manager.clientCache.storageEncryption.kubernetes.serviceAccount=tenant-1' \
        --set 'controller.manager.clientCache.storageEncryption.kubernetes.tokenAudiences={vault,foo}' \
        --set 'controller.manager.clientCache.storageEncryption.headers.foo=bar' \
        --set 'controller.manager.clientCache.storageEncryption.params.foo=baz' \
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

    actual=$(echo "$object" | yq '.spec.headers | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.headers."foo"' | tee /dev/stderr)
    [ "${actual}" = "bar" ]
    actual=$(echo "$object" | yq '.spec.params | length' | tee /dev/stderr)
    [ "${actual}" = "1" ]
    actual=$(echo "$object" | yq '.spec.params."foo"' | tee /dev/stderr)
    [ "${actual}" = "baz" ]
}

@test "defaultTransitAuthMethod/CR: default settings for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.method=jwt' \
        --set 'controller.manager.clientCache.storageEncryption.mount=jwt' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.name' | tee /dev/stderr)
    [ "${actual}" = "release-name-vault-secrets-operator-default-transit-auth" ]
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

@test "defaultTransitAuthMethod/CR: service account and token audiences settings can be modified for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.namespace=tenant-2' \
        --set 'controller.manager.clientCache.storageEncryption.method=jwt' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo' \
        --set 'controller.manager.clientCache.storageEncryption.jwt.role=role-1' \
        --set 'controller.manager.clientCache.storageEncryption.jwt.serviceAccount=tenant-1' \
        --set 'controller.manager.clientCache.storageEncryption.jwt.tokenAudiences={vault,foo}' \
        --set 'controller.manager.clientCache.storageEncryption.headers.foo=bar' \
        --set 'controller.manager.clientCache.storageEncryption.params.foo=baz' \
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

@test "defaultTransitAuthMethod/CR: token secret settings can be modified for jwt auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.namespace=tenant-2' \
        --set 'controller.manager.clientCache.storageEncryption.method=jwt' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo' \
        --set 'controller.manager.clientCache.storageEncryption.jwt.role=role-1' \
        --set 'controller.manager.clientCache.storageEncryption.jwt.secretRef=secret-1' \
        --set 'controller.manager.clientCache.storageEncryption.headers.foo=bar' \
        --set 'controller.manager.clientCache.storageEncryption.params.foo=baz' \
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

@test "defaultTransitAuthMethod/CR: settings can be modified for appRole auth method" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.storageEncryption.enabled=true' \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.method=appRole' \
        --set 'controller.manager.clientCache.storageEncryption.namespace=tenant-2' \
        --set 'controller.manager.clientCache.storageEncryption.appRole.roleid=role-1' \
        --set 'controller.manager.clientCache.storageEncryption.appRole.secretRef=secret-1' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo' \
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
