#!/usr/bin/env bash
# Copyright (c) 2022 HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

set -e

cat <<EOF | kubectl -n demo exec -i vault-0 -- sh -e
vault secrets disable kvv2/
vault secrets enable -path=kvv2 kv-v2
vault kv put kvv2/secret username="db-readonly-username" password="db-secret-password"

vault secrets disable kvv1/
vault secrets enable -path=kvv1 -version=1 kv
vault kv put kvv1/secret username="v1-user" password="v1-password"

vault secrets disable pki
vault secrets enable pki
vault write pki/root/generate/internal \
    common_name=example.com \
    ttl=768h
vault write pki/config/urls \
    issuing_certificates="http://127.0.0.1:8200/v1/pki/ca" \
    crl_distribution_points="http://127.0.0.1:8200/v1/pki/crl"
vault write pki/roles/default \
    allowed_domains=example.com \
    allow_subdomains=true \
    max_ttl=72h

cat <<EOT > /tmp/policy.hcl
path "kvv2/*" {
  capabilities = ["read"]
}
path "kvv1/*" {
  capabilities = ["read"]
}
path "pki/*" {
  capabilities = ["read", "create", "update"]
}
EOT
vault policy write demo /tmp/policy.hcl

# setup the necessary auth backend
vault auth disable kubernetes
vault auth enable kubernetes
vault write auth/kubernetes/config \
    kubernetes_host=https://kubernetes.default.svc
vault write auth/kubernetes/role/demo \
    bound_service_account_names=default \
    bound_service_account_namespaces=tenant-1,tenant-2 \
    policies=demo \
    ttl=1h
EOF

for ns in tenant-{1,2} ; do
    kubectl delete namespace --wait --timeout=30s "${ns}" || true
    kubectl create namespace "${ns}"
done
