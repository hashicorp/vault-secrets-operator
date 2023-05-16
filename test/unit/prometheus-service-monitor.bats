#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# service monitor

@test "prometheus/ServiceMonitor: disabled by default" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/prometheus-service-monitor.yaml  \
      . | tee /dev/stderr |
        yq 'length > 0' | tee /dev/stderr)
   [ "${actual}" = "false" ]
}

@test "prometheus/ServiceMonitor: has default settings when enabled" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/prometheus-service-monitor.yaml  \
      --set 'prometheus.serviceMonitor.enabled=true' \
      . | tee /dev/stderr |
      yq '.spec' | tee /dev/stderr)
   
   local endpoints=$(echo "$object" | yq '.endpoints | map(select(.path == "/metrics"))' | tee /dev/stderr)

   local actual=$(echo "$endpoints" | yq '.[] .port' | tee /dev/stderr)
    [ "${actual}" = "https" ]
   actual=$(echo "$endpoints" | yq '.[] .interval' | tee /dev/stderr)
    [ "${actual}" = "30s" ]
   actual=$(echo "$endpoints" | yq '.[] .scrapeTimeout' | tee /dev/stderr)
    [ "${actual}" = "10s" ]
   actual=$(echo "$endpoints" | yq '.[] .scheme' | tee /dev/stderr)
    [ "${actual}" = "https" ]
   actual=$(echo "$endpoints" | yq '.[] .path' | tee /dev/stderr)
    [ "${actual}" = "/metrics" ]
   actual=$(echo "$endpoints" | yq '.[] .tlsConfig.insecureSkipVerify' | tee /dev/stderr)
    [ "${actual}" = "true" ]

   actual=$(echo "$object" | yq '.selector.matchLabels.control-plane' | tee /dev/stderr)
    [ "${actual}" = "controller-manager" ]
}

@test "prometheus/ServiceMonitor: settings can be changed" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/prometheus-service-monitor.yaml  \
      --set 'prometheus.serviceMonitor.enabled=true' \
      --set 'prometheus.serviceMonitor.endpoint.port=http' \
      --set 'prometheus.serviceMonitor.endpoint.scheme=http' \
      --set 'prometheus.serviceMonitor.endpoint.path=metrics-foo' \
      --set 'prometheus.serviceMonitor.endpoint.interval=45s' \
      --set 'prometheus.serviceMonitor.endpoint.scrapeTimeout=2m' \
      --set 'prometheus.serviceMonitor.endpoint.tlsConfig.insecureSkipVerify=false' \
      --set 'prometheus.serviceMonitor.enabled=true' \
      . | tee /dev/stderr |
      yq '.spec' | tee /dev/stderr)
   
   local endpoints=$(echo "$object" | yq '.endpoints | map(select(.path == "metrics-foo"))' | tee /dev/stderr)

   local actual=$(echo "$endpoints" | yq '.[] .port' | tee /dev/stderr)
    [ "${actual}" = "http" ]
   actual=$(echo "$endpoints" | yq '.[] .interval' | tee /dev/stderr)
    [ "${actual}" = "45s" ]
   actual=$(echo "$endpoints" | yq '.[] .scrapeTimeout' | tee /dev/stderr)
    [ "${actual}" = "2m" ]
   actual=$(echo "$endpoints" | yq '.[] .scheme' | tee /dev/stderr)
    [ "${actual}" = "http" ]
   actual=$(echo "$endpoints" | yq '.[] .path' | tee /dev/stderr)
    [ "${actual}" = "metrics-foo" ]
   actual=$(echo "$endpoints" | yq '.[] .tlsConfig.insecureSkipVerify' | tee /dev/stderr)
    [ "${actual}" = "false" ]

   actual=$(echo "$object" | yq '.selector.matchLabels.control-plane' | tee /dev/stderr)
    [ "${actual}" = "controller-manager" ]
}

