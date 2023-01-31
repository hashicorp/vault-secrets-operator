#!/bin/bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


cat <<EOF > /tmp/vault-commands.sh
vault secrets enable -path=kvv2 kv-v2 || true
vault kv put kvv2/secret username="db-readonly-username" password="db-secret-password"

vault secrets enable -path=kv -version=1 kv || true
vault kv put kv/secret username="v1-user" password="v1-password"

vault secrets enable pki || true
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
EOF

kubectl cp /tmp/vault-commands.sh demo/vault-0:/tmp/
kubectl -n demo exec vault-0 -- sh -c 'sh /tmp/vault-commands.sh'

# create the k8s namespaces for the samples
kubectl create namespace tenant-1 || true
kubectl create namespace tenant-2 || true
