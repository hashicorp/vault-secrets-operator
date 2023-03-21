#!/usr/bin/env bash
# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0


set -e
for n in $(kubectl --namespace vault-secrets-operator-system get secrets -l app.kubernetes.io/component=client-cache-storage  --no-headers|awk '{print $1}' )
do
  data="$(kubectl --namespace vault-secrets-operator-system get secrets $n -o json)" 
  echo ${data} | jq -C
  echo ${data} | jq -r .data.secret  | base64 -d | jq -C
  echo "dumped $n"
done
