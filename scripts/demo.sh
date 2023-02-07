#!/usr/bin/env bash
for n in $(kubectl get pods -n demo-ns | awk '/^vso/{print $1}')
do kubectl exec -n demo-ns $n -- sh -c "echo POD: $n DB_PASSWORD: \$(printenv DB_PASSWORD), DB_USERNAME: \$(printenv DB_USERNAME)" 2> /dev/null
done
