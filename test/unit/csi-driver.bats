#!/usr/bin/env bats
#
# Copyright IBM Corp. 2022, 2026
# SPDX-License-Identifier: BUSL-1.1
#

load _helpers

#--------------------------------------------------------------------
# ServiceAccount Tests

@test "CSIDriver/ServiceAccount: not created when csi.enabled is false" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    . | tee /dev/stderr |
    yq 'select(.kind == "ServiceAccount") | length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver/ServiceAccount: created when csi.enabled is true" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "ServiceAccount") | .kind' | tee /dev/stderr)
  [ "${actual}" = "ServiceAccount" ]
}

@test "CSIDriver/ServiceAccount: labels are correctly set" {
  cd "$(chart_dir)"
  local labels=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "ServiceAccount") | .metadata.labels' | tee /dev/stderr)

  local component=$(echo "$labels" | yq '."app.kubernetes.io/component"')
  [ "$component" = "csi-driver" ]
}

@test "CSIDriver/ServiceAccount: no imagePullSecrets by default" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "ServiceAccount") | .imagePullSecrets' | tee /dev/stderr)

  local actual=$(echo "$object" |
    yq -r '.imagePullSecrets | length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver/ServiceAccount: custom imagePullSecrets can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.imagePullSecrets[0].name=foo' \
    --set 'csi.imagePullSecrets[1].name=bar' \
    . | tee /dev/stderr |
    yq 'select(.kind == "ServiceAccount") | .imagePullSecrets' | tee /dev/stderr)

  local actual=$(echo "$object" | yq -r 'length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" | yq -r '.[0].name' | tee /dev/stderr)
  [ "${actual}" = "foo" ]
  actual=$(echo "$object" | yq -r '.[1].name' | tee /dev/stderr)
  [ "${actual}" = "bar" ]
}

#--------------------------------------------------------------------
# CSIDriver Tests

@test "CSIDriver: not created when csi.enabled is false" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    . | tee /dev/stderr |
    yq 'select(.kind == "CSIDriver") | length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver: created when csi.enabled is true" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "CSIDriver") | .kind' | tee /dev/stderr)
  [ "${actual}" = "CSIDriver" ]
}

@test "CSIDriver: podInfoOnMount and volume lifecycle modes are correctly configured" {
  cd "$(chart_dir)"
  local config=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "CSIDriver") | .spec' | tee /dev/stderr)
  local podInfoOnMount=$(echo "$config" | yq '.podInfoOnMount')
  [ "$podInfoOnMount" = "true" ]
  local volumeLifecycleModes=$(echo "$config" | yq '.volumeLifecycleModes[0]')
  [ "$volumeLifecycleModes" = "Ephemeral" ]
}

@test "CSIDriver: tokenRequests are correctly configured" {
  cd "$(chart_dir)"
  local config=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "CSIDriver") | .spec.tokenRequests' | tee /dev/stderr)
  local audience=$(echo "$config" | yq '.[0].audience')
  [ "$audience" = "csi.vso.hashicorp.com" ]
}

#--------------------------------------------------------------------
# DaemonSet Tests

@test "CSIDriver/DaemonSet: not created when csi.enabled is false" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "CSIDriver/DaemonSet: created when csi.enabled is true" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .kind' | tee /dev/stderr)
  [ "${actual}" = "DaemonSet" ]
}

@test "CSIDriver/DaemonSet: hostAliases not set by default" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.hostAliases' | tee /dev/stderr)

  [ "${object}" = null ]
}

@test "CSIDriver/DaemonSet: custom hostAliases can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.hostAliases[0].ip=192.168.1.100' \
    --set 'csi.hostAliases[0].hostnames={vault.example.com}' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.hostAliases' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.[0] | length' | tee /dev/stderr)
  [ "${actual}" = '2' ]
  actual=$(echo "$object" | yq '.[0].ip' | tee /dev/stderr)
  [ "${actual}" = '192.168.1.100' ]
  actual=$(echo "$object" | yq '.[0].hostnames | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.[0].hostnames[0]' | tee /dev/stderr)
  [ "${actual}" = 'vault.example.com' ]
}

@test "CSIDriver/DaemonSet: nodeSelector set to default kubernetes.io/os: linux" {
  cd "$(chart_dir)"
  local object=$(helm template -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.nodeSelector' | tee /dev/stderr)
  local os=$(echo "$object" | yq '."kubernetes.io/os"')
  [ "$os" = "linux" ]
}

@test "CSIDriver/DaemonSet: nodeSelector includes custom value and default" {
  cd "$(chart_dir)"
  local object=$(helm template -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.nodeSelector.custom-key=custom-value' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.nodeSelector' | tee /dev/stderr)

  local custom_value=$(echo "$object" | yq '."custom-key"')
  [ "$custom_value" = "custom-value" ]
  local os=$(echo "$object" | yq '."kubernetes.io/os"')
  [ "$os" = "linux" ]
}

@test "CSIDriver/DaemonSet: tolerations set to default operator: Exists" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.tolerations' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '.[0]."operator"' | tee /dev/stderr)
  [ "${actual}" = "Exists" ]
}

@test "CSIDriver/DaemonSet: custom tolerations can be set and includes default" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.tolerations[0].key=key1' \
    --set 'csi.tolerations[0].operator=Equal' \
    --set 'csi.tolerations[0].value=value1' \
    --set 'csi.tolerations[0].effect=NoSchedule' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.tolerations' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" | yq '.[0].key' | tee /dev/stderr)
  [ "${actual}" = "key1" ]
  actual=$(echo "$object" | yq '.[0].operator' | tee /dev/stderr)
  [ "${actual}" = "Equal" ]
  actual=$(echo "$object" | yq '.[0].value' | tee /dev/stderr)
  [ "${actual}" = "value1" ]
  actual=$(echo "$object" | yq '.[0].effect' | tee /dev/stderr)
  [ "${actual}" = "NoSchedule" ]

  local default_operator=$(echo "$object" | yq '.[1].operator' | tee /dev/stderr)
  [ "${default_operator}" = "Exists" ]
}

@test "CSIDriver/DaemonSet: operator Exists toleration is not duplicated if specified by user" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.tolerations[0].operator=Exists' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.tolerations' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" | yq '.[0].operator' | tee /dev/stderr)
  [ "${actual}" = "Exists" ]
}

@test "CSIDriver/DaemonSet: default affinity is an empty object" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.affinity' | tee /dev/stderr)
  [ "$actual" = null ]
}

@test "CSIDriver/DaemonSet: affinity can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set "csi.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=topology.kubernetes.io/zone" \
    --set "csi.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In" \
    --set "csi.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values={antarctica-east1,antarctica-west1}" \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.affinity' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0] | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0] | length' | tee /dev/stderr)
  [ "${actual}" = '3' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key' | tee /dev/stderr)
  [ "${actual}" = 'topology.kubernetes.io/zone' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator' | tee /dev/stderr)
  [ "${actual}" = 'In' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values | length' | tee /dev/stderr)
  [ "${actual}" = '2' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[0]' | tee /dev/stderr)
  [ "${actual}" = 'antarctica-east1' ]
  actual=$(echo "$object" | yq '.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values[1]' | tee /dev/stderr)
  [ "${actual}" = 'antarctica-west1' ]
}

@test "CSIDriver/DaemonSet: annotations set to default" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.metadata.annotations' | tee /dev/stderr)
  local annotations=$(echo "$actual" | yq '."kubectl.kubernetes.io/default-container"')
  [ "$annotations" = "secrets-store" ]
}

@test "CSIDriver/DaemonSet: annotations include custom value and default" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.annotations.annotationKey=annotationValue' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.metadata.annotations' | tee /dev/stderr)
  local annotationValue=$(echo "$actual" | yq '.annotationKey')
  [ "$annotationValue" = "annotationValue" ]
  local defaultAnnotation=$(echo "$actual" | yq '."kubectl.kubernetes.io/default-container"')
  [ "$defaultAnnotation" = "secrets-store" ]
}

@test "CSIDriver/DaemonSet: driver image defaults" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.containers[1].image' | tee /dev/stderr)
  [ "${actual}" = "hashicorp/vault-secrets-operator-csi:1.0.1" ]
}

@test "CSIDriver/DaemonSet: custom driver image can be set" {
  cd "$(chart_dir)"
  local actual=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.driver.image.repository=custom-repo' \
    --set 'csi.driver.image.tag=1.2.3' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.containers[1].image' | tee /dev/stderr)
  [ "${actual}" = "custom-repo:1.2.3" ]
}

@test "CSIDriver/DaemonSet: extraEnv variables aren't set by default" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.containers[1].env' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
}

@test "CSIDriver/DaemonSet: extraEnv variables can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.driver.extraEnv[0].name=HTTP_PROXY' \
    --set 'csi.driver.extraEnv[0].value=http://proxy.example.com' \
    --set 'csi.driver.extraEnv[1].name=VSO_OUTPUT_FORMAT' \
    --set 'csi.driver.extraEnv[1].value=json' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet") | .spec.template.spec.containers[1].env' | tee /dev/stderr)

  local proxy=$(echo "$object" | yq '.[2].name')
  [ "$proxy" = "HTTP_PROXY" ]
  local proxy_value=$(echo "$object" | yq '.[2].value')
  [ "$proxy_value" = "http://proxy.example.com" ]

  local output_format=$(echo "$object" | yq '.[3].name')
  [ "$output_format" = "VSO_OUTPUT_FORMAT" ]
  local format_value=$(echo "$object" | yq '.[3].value')
  [ "$format_value" = "json" ]
}

@test "CSIDriver/DaemonSet: extraArgs not set by default" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "10" ]
}

@test "CSIDriver/DaemonSet: with extraArgs" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.driver.extraArgs={--foo=baz,--bar=qux}' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "12" ]
  actual=$(echo "$object" | yq '.[10]' | tee /dev/stderr)
  [ "${actual}" = "--foo=baz" ]
  actual=$(echo "$object" | yq '.[11]' | tee /dev/stderr)
  [ "${actual}" = "--bar=qux" ]
}

@test "CSIDriver/DaemonSet: driver logging defaults" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app.kubernetes.io/component" == "csi-driver" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "10" ]
  local actual_log_level=$(echo "$object" | yq '.[2]' | tee /dev/stderr)
  [ "${actual_log_level}" = "--zap-log-level=info" ]
  local actual_time_encoding=$(echo "$object" | yq '.[3]' | tee /dev/stderr)
  [ "${actual_time_encoding}" = "--zap-time-encoding=rfc3339" ]
  local actual_stacktrace_level=$(echo "$object" | yq '.[4]' | tee /dev/stderr)
  [ "${actual_stacktrace_level}" = "--zap-stacktrace-level=panic" ]
}

@test "CSIDriver/DaemonSet: driver logging custom values" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.driver.logging.level=debug' \
    --set 'csi.driver.logging.timeEncoding=millis' \
    --set 'csi.driver.logging.stacktraceLevel=error' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app.kubernetes.io/component" == "csi-driver" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "10" ]
  local actual_log_level=$(echo "$object" | yq '.[2]' | tee /dev/stderr)
  [ "${actual_log_level}" = "--zap-log-level=debug" ]
  local actual_time_encoding=$(echo "$object" | yq '.[3]' | tee /dev/stderr)
  [ "${actual_time_encoding}" = "--zap-time-encoding=millis" ]
  local actual_stacktrace_level=$(echo "$object" | yq '.[4]' | tee /dev/stderr)
  [ "${actual_stacktrace_level}" = "--zap-stacktrace-level=error" ]
}

@test "CSIDriver/DaemonSet: livenessProbe args are set correctly" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "liveness-probe")' | tee /dev/stderr)

  local liveness_probe_image=$(echo "$object" | yq '.image')
  [ "$liveness_probe_image" = "registry.k8s.io/sig-storage/livenessprobe:v2.16.0" ]

  local liveness_probe_args=$(echo "$object" | yq '.args')
  local actual_length=$(echo "$liveness_probe_args" | yq '. | length')
  [ "$actual_length" = "4" ]

  local actual=$(echo "$liveness_probe_args" | yq '.[0]')
  [ "$actual" = "--csi-address=/csi/csi.sock" ]
  actual=$(echo "$liveness_probe_args" | yq '.[1]')
  [ "$actual" = "--probe-timeout=3s" ]
  actual=$(echo "$liveness_probe_args" | yq '.[2]')
  [ "$actual" = "--http-endpoint=0.0.0.0:9808" ]
  actual=$(echo "$liveness_probe_args" | yq '.[3]')
  [ "$actual" = "-v=2" ]
}

@test "CSIDriver/DaemonSet: custom livenessProbe args can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.livenessProbe.extraArgs[0]=--foo=baz' \
    --set 'csi.livenessProbe.extraArgs[1]=--bar-arg=qux' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "liveness-probe")' | tee /dev/stderr)

  local liveness_probe_image=$(echo "$object" | yq '.image')
  [ "$liveness_probe_image" = "registry.k8s.io/sig-storage/livenessprobe:v2.16.0" ]

  local liveness_probe_args=$(echo "$object" | yq '.args')
  local actual_length=$(echo "$liveness_probe_args" | yq '. | length')
  [ "$actual_length" = "6" ]

  local actual=$(echo "$liveness_probe_args" | yq '.[4]')
  [ "$actual" = "--foo=baz" ]
  actual=$(echo "$liveness_probe_args" | yq '.[5]')
  [ "$actual" = "--bar-arg=qux" ]
}

@test "CSIDriver/DaemonSet: nodeDriverRegistrar args set correctly" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "node-driver-registrar") | .args' | tee /dev/stderr)

  local actual_length=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual_length}" = "3" ]
  actual=$(echo "$object" | yq '.[0]')
  [ "$actual" = "--v=5" ]
  actual=$(echo "$object" | yq '.[1]')
  [ "$actual" = "--csi-address=/csi/csi.sock" ]
  actual=$(echo "$object" | yq '.[2]')
  [ "$actual" = "--kubelet-registration-path=/var/lib/kubelet/plugins/vso-csi/csi.sock" ]
}

@test "CSIDriver/DaemonSet: custom extraArgs for nodeDriverRegistrar can be set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.nodeDriverRegistrar.extraArgs[0]=--foo=baz' \
    --set 'csi.nodeDriverRegistrar.extraArgs[1]=--bar=qux' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "node-driver-registrar") | .args' | tee /dev/stderr)

  local actual_length=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual_length}" = "5" ]
  local actual=$(echo "$object" | yq '.[3]' | tee /dev/stderr)
  [ "$actual" = "--foo=baz" ]
  actual=$(echo "$object" | yq '.[4]' | tee /dev/stderr)
  [ "$actual" = "--bar=qux" ]
}

@test "CSIDriver/DaemonSet: without updateStrategy" {
  cd "$(chart_dir)"
  local object=$(
    helm template \
      -s templates/csi-driver.yaml \
      --set 'csi.enabled=true'
    . | tee /dev/stderr |
      yq 'select(.kind == "DaemonSet") and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec' | tee /dev/stderr
  )

  local actual=$(echo "$object" | yq '.strategy' | tee /dev/stderr)
  [ "${actual}" = "null" ]
}

@test "CSIDriver/DaemonSet: with rollingUpdate strategy" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.updateStrategy.type=rollingUpdate' \
    --set 'csi.updateStrategy.rollingUpdate.maxSurge=1' \
    --set 'csi.updateStrategy.rollingUpdate.maxUnavailable=1' \
    . |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '.updateStrategy | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" | yq '.updateStrategy.type' | tee /dev/stderr)
  [ "${actual}" = "rollingUpdate" ]
  actual=$(echo "$object" | yq '.updateStrategy.rollingUpdate | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" | yq '.updateStrategy.rollingUpdate.maxSurge' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" | yq '.updateStrategy.rollingUpdate.maxUnavailable' | tee /dev/stderr)
  [ "${actual}" = "1" ]
}

@test "CSIDriver/DaemonSet: with backoffOnSecretSourceErrorCSI defaults" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "10" ]
  actual=$(echo "$object" | yq '.[5]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-initial-interval=5s" ]
  actual=$(echo "$object" | yq '.[6]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-max-interval=60s" ]
  actual=$(echo "$object" | yq '.[7]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-max-elapsed-time=0s" ]
  actual=$(echo "$object" | yq '.[8]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-multiplier=1.50" ]
  actual=$(echo "$object" | yq '.[9]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-randomization-factor=0.50" ]
}

@test "CSIDriver/DaemonSet: with backoffOnSecretSourceErrorCSI set" {
  cd "$(chart_dir)"
  local object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.driver.backoffOnSecretSourceError.initialInterval=30s' \
    --set 'csi.driver.backoffOnSecretSourceError.maxInterval=300s' \
    --set 'csi.driver.backoffOnSecretSourceError.maxElapsedTime=24h' \
    --set 'csi.driver.backoffOnSecretSourceError.multiplier=2.5' \
    --set 'csi.driver.backoffOnSecretSourceError.randomizationFactor=3.7361' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet" and .metadata.labels."app" == "vault-secrets-operator-csi") | .spec.template.spec.containers[] | select(.name == "driver") | .args' | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = "10" ]
  actual=$(echo "$object" | yq '.[5]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-initial-interval=30s" ]
  actual=$(echo "$object" | yq '.[6]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-max-interval=300s" ]
  actual=$(echo "$object" | yq '.[7]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-max-elapsed-time=24h" ]
  actual=$(echo "$object" | yq '.[8]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-multiplier=2.50" ]
  actual=$(echo "$object" | yq '.[9]' | tee /dev/stderr)
  [ "${actual}" = "--backoff-randomization-factor=3.74" ]
}

@test "CSIDriver/DaemonSet: securityContext privileged always enabled default" {
  cd "$(chart_dir)"
  local object
  object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet")' | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | length' | tee /dev/stderr)
  [ "${actual}" = '0' ]

  local driverObj
  driverObj=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "driver") | .securityContext')
  actual=$(echo "$driverObj" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$driverObj" | yq '.privileged | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'true' ]
}

@test "CSIDriver/DaemonSet: securityContext privileged always enabled ignoring override" {
  cd "$(chart_dir)"
  local object
  object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.securityContext.fsGroup=101' \
    --set 'csi.driver.securityContext.privileged=baz' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet")' | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext.fsGroup' | tee /dev/stderr)
  [ "${actual}" = '101' ]

  local driverObj
  driverObj=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "driver") | .securityContext')
  actual=$(echo "$driverObj" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$driverObj" | yq '.privileged | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'true' ]
}

@test "CSIDriver/DaemonSet: Pod level securityContext only" {
  cd "$(chart_dir)"
  local object
  object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.securityContext.allowPrivilegeEscalation=false' \
    --set 'csi.securityContext.fsGroup=101' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet")' | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | length' | tee /dev/stderr)
  [ "${actual}" = '2' ]
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | .allowPrivilegeEscalation | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'false' ]
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext.fsGroup' | tee /dev/stderr)
  [ "${actual}" = '101' ]

  local driverObj
  driverObj=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "driver") | .securityContext')
  actual=$(echo "$driverObj" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '1' ]
  actual=$(echo "$driverObj" | yq '.privileged | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'true' ]
}

@test "CSIDriver/DaemonSet: securityContext set on driver container" {
  cd "$(chart_dir)"
  local object
  object=$(helm template \
    -s templates/csi-driver.yaml \
    --set 'csi.enabled=true' \
    --set 'csi.securityContext.runAsNonRoot=true' \
    --set 'csi.securityContext.fsGroup=101' \
    --set 'csi.driver.securityContext.allowPrivilegeEscalation=false' \
    . | tee /dev/stderr |
    yq 'select(.kind == "DaemonSet")' \
      | tee /dev/stderr)

  local actual
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | length' | tee /dev/stderr)
  [ "${actual}" = '2' ]
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext | .runAsNonRoot | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'true' ]
  actual=$(echo "$object" | yq '.spec.template.spec.securityContext.fsGroup' | tee /dev/stderr)
  [ "${actual}" = '101' ]

  local driverObj
  driverObj=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "driver") | .securityContext')
  actual=$(echo "$driverObj" | yq '. | length' | tee /dev/stderr)
  [ "${actual}" = '2' ]
  actual=$(echo "$driverObj" | yq '.privileged | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'true' ]
  actual=$(echo "$driverObj" | yq '.allowPrivilegeEscalation | select(tag == "!!bool")' | tee /dev/stderr)
  [ "${actual}" = 'false' ]
}
