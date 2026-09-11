#!/usr/bin/env bats

load _helpers

@test "prometheus/ServiceMonitor-server: assertDisabled in values" {
  cd `chart_dir`
  local actual=$(cat values.yaml | yq '.telemetry.serviceMonitor.enabled' | tee /dev/stderr)
    [ "${actual}" == "false" ]
}

@test "prometheus/ServiceMonitor-server: assertDisabled by default" {
  cd `chart_dir`
  local actual=$(helm template \
      . | tee /dev/stderr |
      yq 'select(.kind == "ServiceMonitor" and .metadata.labels."control-plane" == "controller-manager") | documentIndex' | tee /dev/stderr)
  [ "${actual}" = "" ]
}

@test "prometheus/ServiceMonitor-server: assertEnabled" {
  cd `chart_dir`
  local actual=$(helm template \
      --set 'telemetry.serviceMonitor.enabled=true' \
      . | tee /dev/stderr |
      yq 'select(.kind == "ServiceMonitor" and .metadata.labels."control-plane" == "controller-manager") | documentIndex' | tee /dev/stderr)
  [ "${actual}" -ge 0 ]
}

@test "prometheus/ServiceMonitor-server: assertScrapeTimeout default" {
  cd `chart_dir`
  local actual=$(helm template \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --show-only templates/prometheus-servicemonitor.yaml \
      .  | tee /dev/stderr |
      yq -r '.spec.endpoints[0].scrapeTimeout' | tee /dev/stderr)
  [ "${actual}" = "10s" ]
}

@test "prometheus/ServiceMonitor-server: assertScrapeTimeout update" {
  cd `chart_dir`
  local actual=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --set 'telemetry.serviceMonitor.scrapeTimeout=60s' \
      . | tee /dev/stderr |
      yq -r '.spec.endpoints[0].scrapeTimeout' | tee /dev/stderr)
  [ "${actual}" = "60s" ]
}

@test "prometheus/ServiceMonitor-server: assertInterval default" {
  cd `chart_dir`
  local actual=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      . | tee /dev/stderr |
      yq -r '.spec.endpoints[0].interval' | tee /dev/stderr)
  [ "${actual}" = "30s" ]
}

@test "prometheus/ServiceMonitor-server: assertInterval update" {
  cd `chart_dir`
  local actual=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --set 'telemetry.serviceMonitor.interval=60s' \
      . | tee /dev/stderr |
      yq -r '.spec.endpoints[0].interval' | tee /dev/stderr)
  [ "${actual}" = "60s" ]
}

@test "prometheus/ServiceMonitor-server: assertSelectors default" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      .  | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.metadata.labels | length')" = "7" ]
  [ "$(echo "$output" | yq -r '.metadata.labels.control-plane')" = "controller-manager" ]
}

@test "prometheus/ServiceMonitor-server: assertSelectors override" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --set 'telemetry.serviceMonitor.selectors.baz=qux' \
      --set 'telemetry.serviceMonitor.selectors.bar=foo' \
      . | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.metadata.labels | length')" = "9" ]
  [ "$(echo "$output" | yq -r '.metadata.labels | has("app")')" = "false" ]
  [ "$(echo "$output" | yq -r '.metadata.labels.baz')" = "qux" ]
  [ "$(echo "$output" | yq -r '.metadata.labels.bar')" = "foo" ]
}

@test "prometheus/ServiceMonitor-server: assertEndpoints default" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      . | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.spec.endpoints | length')" = "1" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].scheme')" = "https" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].port')" = "https" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].bearerTokenFile')" = "/var/run/secrets/kubernetes.io/serviceaccount/token" ]
}

@test "prometheus/ServiceMonitor-server: assertEndpoints update" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --set 'telemetry.serviceMonitor.scheme=http' \
      --set 'telemetry.serviceMonitor.port=http' \
      --set 'telemetry.serviceMonitor.bearerTokenFile=/foo/token' \
      . | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.spec.endpoints | length')" = "1" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].scheme')" = "http" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].port')" = "http" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].bearerTokenFile')" = "/foo/token" ]
}

@test "prometheus/ServiceMonitor-server: assertRelabellings default" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      . | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.spec.endpoints | length')" = "1" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0] | has("relabelings")')" = "false" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0] | has("metricRelabelings")')" = "false" ]
}

@test "prometheus/ServiceMonitor-server: assertRelabellings update" {
  cd `chart_dir`
  local output=$(helm template \
      --show-only templates/prometheus-servicemonitor.yaml \
      --set 'telemetry.serviceMonitor.enabled=true' \
      --set 'telemetry.serviceMonitor.relabelings[0].sourceLabels[0]=__meta_kubernetes_endpoint_node_name' \
      --set 'telemetry.serviceMonitor.relabelings[0].targetLabel=nodename' \
      --set 'telemetry.serviceMonitor.metricRelabelings[0].sourceLabels[0]=__name__' \
      --set 'telemetry.serviceMonitor.metricRelabelings[0].regex=controller_runtime_.*' \
      --set 'telemetry.serviceMonitor.metricRelabelings[0].action=keep' \
      . | tee /dev/stderr)

  [ "$(echo "$output" | yq -r '.spec.endpoints | length')" = "1" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].relabelings[0].sourceLabels[0]')" = "__meta_kubernetes_endpoint_node_name" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].relabelings[0].targetLabel')" = "nodename" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].metricRelabelings[0].sourceLabels[0]')" = "__name__" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].metricRelabelings[0].regex')" = "controller_runtime_.*" ]
  [ "$(echo "$output" | yq -r '.spec.endpoints[0].metricRelabelings[0].action')" = "keep" ]
}
