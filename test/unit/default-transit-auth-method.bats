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

@test "defaultTransitAuthMethod/CR: serviceaccount uses operator sa as a default" {
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
        --set 'controller.manager.clientCache.storageEncryption.namespace=foo-ns' \
        --set 'controller.manager.clientCache.storageEncryption.serviceAccount=foo-sa' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo-mount' \
        --set 'controller.manager.clientCache.storageEncryption.role=foo-role' \
        --set 'controller.manager.clientCache.storageEncryption.tokenAudiences={vault,foo}' \
        --set 'controller.manager.clientCache.storageEncryption.keyName=foo-keyName' \
        --set 'controller.manager.clientCache.storageEncryption.transitMount=foo-transit-mount' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.spec.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "default" ]
}

@test "defaultTransitAuthMethod/CR: settings can be modified" {
    cd `chart_dir`
    local object=$(helm template \
        -s templates/default-transit-auth-method.yaml  \
        --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
        --set 'controller.manager.clientCache.storageEncryption.namespace=foo-ns' \
        --set 'controller.manager.clientCache.storageEncryption.serviceAccount=foo-sa' \
        --set 'controller.manager.clientCache.storageEncryption.mount=foo-mount' \
        --set 'controller.manager.clientCache.storageEncryption.role=foo-role' \
        --set 'controller.manager.clientCache.storageEncryption.tokenAudiences={vault,foo}' \
        --set 'controller.manager.clientCache.storageEncryption.keyName=foo-keyName' \
        --set 'controller.manager.clientCache.storageEncryption.transitMount=foo-transit-mount' \
        --set 'controller.manager.clientCache.storageEncryption.vaultConnectionRef=foo' \
        . | tee /dev/stderr)

    local actual=$(echo "$object" | yq '.metadata.namespace' | tee /dev/stderr)
     [ "${actual}" = "default" ]
    actual=$(echo "$object" | yq '.spec.namespace' | tee /dev/stderr)
     [ "${actual}" = "foo-ns" ]

    actual=$(echo "$object" | yq '.spec.method' | tee /dev/stderr)
     [ "${actual}" = "kubernetes" ]
    actual=$(echo "$object" | yq '.spec.mount' | tee /dev/stderr)
     [ "${actual}" = "foo-mount" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.role' | tee /dev/stderr)
     [ "${actual}" = "foo-role" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.serviceAccount' | tee /dev/stderr)
     [ "${actual}" = "foo-sa" ]
    actual=$(echo "$object" | yq '.spec.kubernetes.audiences' | tee /dev/stderr)
     [ "${actual}" = '["vault", "foo"]' ]
    actual=$(echo "$object" | yq '.spec.storageEncryption.keyName' | tee /dev/stderr)
     [ "${actual}" = "foo-keyName" ]
    actual=$(echo "$object" | yq '.spec.storageEncryption.mount' | tee /dev/stderr)
     [ "${actual}" = "foo-transit-mount" ]
    actual=$(echo "$object" | yq '.spec.vaultConnectionRef' | tee /dev/stderr)
     [ "${actual}" = "foo" ]
}
