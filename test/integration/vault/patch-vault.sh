#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

set -e

K8S_VAULT_NAMESPACE="${K8S_VAULT_NAMESPACE:-demo}"

# convenient if you are running non-Vault acceptance tests.
if [ -n "${SKIP_PATCH_VAULT}" ]; then
    echo "SKIP_PATCH_VAULT is set" >&2
    exit 0
fi

function waitVaultPod() {
    echo "waiting for the vault pod to become Ready"
    local tries=0
    until [ $tries -gt 5 ]
    do
        kubectl wait --namespace=${K8S_VAULT_NAMESPACE} \
            --for=condition=Ready \
            --timeout=1m pod -l \
            app.kubernetes.io/name=vault &> /dev/null && return 0
        ((++tries))
        sleep .5
    done
    echo "failed waiting for the vault become Ready" >&2
}

# Apply patches first, before waiting for the pod
# This ensures critical patches (like IPC_LOCK) are applied before the pod starts
root="${0%/*}"
pushd ${root}/patches > /dev/null
for f in *.yaml
do
    type=
    case "${f}" in
      statefulset-*)
        type=statefulset
      ;;
      *)
        echo "unsupported patch file ${f}, skipping" >&2
        continue
        ;;
    esac
    echo "Applying patch: ${f}"
    kubectl patch --namespace=${K8S_VAULT_NAMESPACE} ${type} vault --patch-file ${f}
done
popd > /dev/null

# Delete the pod so it gets recreated with the patches
echo "Deleting vault-0 pod to apply patches..."
kubectl delete --wait --timeout=30s --namespace=${K8S_VAULT_NAMESPACE} pod vault-0 2>/dev/null || true

# Now wait for the patched pod to become ready
waitVaultPod || exit 1

exit 0
