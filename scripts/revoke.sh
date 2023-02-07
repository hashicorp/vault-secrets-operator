#!/usr/bin/env bash
export VAULT_ADDR=http://127.0.0.1:38302
export VAULT_TOKEN=root

prefix=demo
lease_id="$(kubectl --namespace ${prefix}-ns get vaultdynamicsecrets vso-db-demo  -o json | jq -r '.status.secretLease.ID')"
echo "Revoking lease ID ${lease_id}"
vault lease revoke -namespace ${prefix}-ns ${lease_id}
