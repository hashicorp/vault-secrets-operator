#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# data

@test "managerConfig: configmap has defaults" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/manager-config.yaml  \
      . | tee /dev/stderr |
      yq '.data["controller_manager_config.yaml"]' | tee /dev/stderr)

   local actual=$(echo "$object" | yq  '.health.healthProbeBindAddress' | tee /dev/stderr)
    [ "${actual}" = ":8081" ]
   local actual=$(echo "$object" | yq  '.leaderElection.leaderElect' | tee /dev/stderr)
    [ "${actual}" = "true" ]
   local actual=$(echo "$object" | yq  '.leaderElection.resourceName' | tee /dev/stderr)
    [ "${actual}" = "b0d477c0.hashicorp.com" ]
   local actual=$(echo "$object" | yq  '.metrics.bindAddress' | tee /dev/stderr)
    [ "${actual}" = "127.0.0.1:8080" ]
   local actual=$(echo "$object" | yq  '.webhook.port' | tee /dev/stderr)
    [ "${actual}" = "9443" ]
}

@test "managerConfig: configmap can be modified" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/manager-config.yaml  \
      --set 'managerConfig.controllerManagerConfigYaml.health.healthProbeBindAddress=:9091' \
      --set 'managerConfig.controllerManagerConfigYaml.leaderElection.leaderElect=false' \
      --set 'managerConfig.controllerManagerConfigYaml.leaderElection.resourceName=foo.bar' \
      --set 'managerConfig.controllerManagerConfigYaml.metrics.bindAddress=127.0.0.1:10091' \
      --set 'managerConfig.controllerManagerConfigYaml.webhook.port=9091' \
      . | tee /dev/stderr |
      yq '.data["controller_manager_config.yaml"]' | tee /dev/stderr)

   local actual=$(echo "$object" | yq  '.health.healthProbeBindAddress' | tee /dev/stderr)
    [ "${actual}" = ":9091" ]
   local actual=$(echo "$object" | yq  '.leaderElection.leaderElect' | tee /dev/stderr)
    [ "${actual}" = "false" ]
   local actual=$(echo "$object" | yq  '.leaderElection.resourceName' | tee /dev/stderr)
    [ "${actual}" = "foo.bar" ]
   local actual=$(echo "$object" | yq  '.metrics.bindAddress' | tee /dev/stderr)
    [ "${actual}" = "127.0.0.1:10091" ]
   local actual=$(echo "$object" | yq  '.webhook.port' | tee /dev/stderr)
    [ "${actual}" = "9091" ]
}

