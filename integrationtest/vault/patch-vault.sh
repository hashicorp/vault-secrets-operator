#!/usr/bin/env bash
set -e

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
    kubectl patch --namespace=${K8S_VAULT_NAMESPACE} ${type} vault --patch-file ${f}
done
popd > /dev/null

kubectl delete --wait --timeout=30s --namespace=${K8S_VAULT_NAMESPACE} pod vault-0
tries=0
until [ $tries -gt 20 ]
do
    kubectl wait --namespace=${K8S_VAULT_NAMESPACE} \
        --for=condition=Ready \
        --timeout=5m pod -l \
        app.kubernetes.io/name=vault && exit 0
    ((++tries))
    sleep .5
done

exit 1
