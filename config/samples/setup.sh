#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e
make setup-kind
make setup-integration-test

cat <<EOF | kubectl -n vault exec -i vault-0 -- sh -e
vault secrets disable kvv2/
vault secrets enable -path=kvv2 kv-v2
vault kv put kvv2/secret username="db-readonly-username" password="db-secret-password"

vault secrets disable kvv1/
vault secrets enable -path=kvv1 -version=1 kv
vault kv put kvv1/secret username="v1-user" password="v1-password"

cat <<EOT > /tmp/policy.hcl
path "kvv2/*" {
  capabilities = ["read"]
  subscribe_event_types = ["kv*"]
}
path "kvv1/*" {
  capabilities = ["read"]
  subscribe_event_types = ["kv*"]
}
path "sys/events/subscribe/*" {
    capabilities = ["read"]
}
EOT
vault policy write demo /tmp/policy.hcl

# setup the necessary auth backend
vault auth disable kubernetes
vault auth enable kubernetes

vault auth tune -default-lease-ttl=30s -max-lease-ttl=1m kubernetes

vault write auth/kubernetes/config \
    kubernetes_host=https://kubernetes.default.svc

vault write auth/kubernetes/role/demo \
    bound_service_account_names=default \
    bound_service_account_namespaces=tenant-1,tenant-2 \
    policies=demo \
    token_ttl=30s \
    token_max_ttl=30s \
    token_explicit_max_ttl=30s
EOF

for ns in tenant-{1,2} ; do
    kubectl delete namespace --wait --timeout=30s "${ns}" &> /dev/null || true
    kubectl create namespace "${ns}"
done

make build docker-build deploy-kind
kubectl apply -f config/samples/secrets_v1beta1_vaultconnection.yaml
kubectl apply -f config/samples/secrets_v1beta1_vaultauth.yaml
kubectl apply -f config/samples/secrets_v1beta1_vaultstaticsecret.yaml
