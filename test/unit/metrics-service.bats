#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# service type

@test "metrics/Service: service type defaults to ClusterIP" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/metrics-service.yaml  \
      . | tee /dev/stderr |
      yq '.spec.type' | tee /dev/stderr)
  [ "${actual}" = "ClusterIP" ]
}

@test "metrics/Service: service type can be set" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/metrics-service.yaml  \
      --set 'metricsService.type=foo' \
      . | tee /dev/stderr |
      yq '.spec.type' | tee /dev/stderr)
  [ "${actual}" = "foo" ]
}

#--------------------------------------------------------------------
# port

@test "metrics/Service: metrics port has default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/metrics-service.yaml  \
      . | tee /dev/stderr |
      yq '.spec.ports[0]' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.name' | tee /dev/stderr)
    [ "${actual}" = "https" ]
   local actual=$(echo "$object" | yq '.port' | tee /dev/stderr)
    [ "${actual}" = "8443" ]
   local actual=$(echo "$object" | yq '.protocol' | tee /dev/stderr)
    [ "${actual}" = "TCP" ]
   local actual=$(echo "$object" | yq '.targetPort' | tee /dev/stderr)
    [ "${actual}" = "https" ]
}

@test "metrics/Service: metrics port can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/metrics-service.yaml  \
      --set 'metricsService.ports[0].name=foo' \
      --set 'metricsService.ports[0].port=8080' \
      --set 'metricsService.ports[0].protocol=UDP' \
      --set 'metricsService.ports[0].targetPort=http' \
      . | tee /dev/stderr |
      yq '.spec.ports[0]' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.name' | tee /dev/stderr)
    [ "${actual}" = "foo" ]
   local actual=$(echo "$object" | yq '.port' | tee /dev/stderr)
    [ "${actual}" = "8080" ]
   local actual=$(echo "$object" | yq '.protocol' | tee /dev/stderr)
    [ "${actual}" = "UDP" ]
   local actual=$(echo "$object" | yq '.targetPort' | tee /dev/stderr)
    [ "${actual}" = "http" ]
}

