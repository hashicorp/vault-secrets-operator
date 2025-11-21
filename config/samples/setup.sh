#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

cat <<EOF | kubectl -n vault exec -i vault-0 -- sh -e
vault --version
vault secrets disable kvv2/
vault secrets enable -path=kvv2 kv-v2
vault kv put kvv2/secret username="db-readonly-username" password="db-secret-password"

vault secrets disable database
vault secrets enable database

vault write database/config/my-postgresql-database \
    plugin_name="postgresql-database-plugin" \
    allowed_roles="my-role" \
    connection_url="postgresql://{{username}}:{{password}}@ep-ancient-sun-adwh40re-pooler.c-2.us-east-1.aws.neon.tech/neondb" \
    username="neondb_owner" \
    password="npg_2HqMNfVzOgR6" \
    password_authentication="password"

vault write database/roles/my-role \
    db_name=my-postgresql-database \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="15m" \
    max_ttl="15m"

vault write database/roles/db-static-role \
    db_name=my-postgresql-database \
    rotation_period=86400 \
    username=static-role

vault secrets disable ldap
vault secrets enable ldap

vault write ldap/config \
    binddn="cn=admin,dc=example,dc=com" \
    bindpass="admin_password" \
    url="ldap://openldap:389"

vault write ldap/static-role/my-static-role \
    dn="uid=testuser,ou=users,dc=example,dc=com" \
    username="testuser" \
    rotation_period="24h"

cat <<EOT > /tmp/policy.hcl
path "kvv2/data/secret" {
   capabilities = ["read", "list", "subscribe"]
   subscribe_event_types = ["kv*"]
}
path "database/*" {
  capabilities = ["read", "create", "update", "subscribe"]
  subscribe_event_types=["database*"]
}
path "ldap/*" {
  capabilities = ["read", "subscribe"]
  subscribe_event_types = ["ldap*"]
}
path "sys/events/subscribe/*" {
    capabilities = ["read"]
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
    kubectl delete namespace --wait --timeout=30s "${ns}" &> /dev/null || true
    kubectl create namespace "${ns}"
done
