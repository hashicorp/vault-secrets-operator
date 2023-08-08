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
   actual=$(echo "$object" | yq  '.leaderElection.leaderElect' | tee /dev/stderr)
    [ "${actual}" = "true" ]
   actual=$(echo "$object" | yq  '.leaderElection.resourceName' | tee /dev/stderr)
    [ "${actual}" = "b0d477c0.hashicorp.com" ]
   actual=$(echo "$object" | yq  '.metrics.bindAddress' | tee /dev/stderr)
    [ "${actual}" = "127.0.0.1:8080" ]
   actual=$(echo "$object" | yq  '.webhook.port' | tee /dev/stderr)
    [ "${actual}" = "9443" ]
}

@test "managerConfig: configmap can be modified" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/manager-config.yaml  \
      --set 'controller.controllerConfigMapYaml.health.healthProbeBindAddress=:9091' \
      --set 'controller.controllerConfigMapYaml.leaderElection.leaderElect=false' \
      --set 'controller.controllerConfigMapYaml.leaderElection.resourceName=foo.bar' \
      --set 'controller.controllerConfigMapYaml.metrics.bindAddress=127.0.0.1:10091' \
      --set 'controller.controllerConfigMapYaml.webhook.port=9091' \
      . | tee /dev/stderr |
      yq '.data["controller_manager_config.yaml"]' | tee /dev/stderr)

   local actual=$(echo "$object" | yq  '.health.healthProbeBindAddress' | tee /dev/stderr)
    [ "${actual}" = ":9091" ]
   actual=$(echo "$object" | yq  '.leaderElection.leaderElect' | tee /dev/stderr)
    [ "${actual}" = "false" ]
   actual=$(echo "$object" | yq  '.leaderElection.resourceName' | tee /dev/stderr)
    [ "${actual}" = "foo.bar" ]
   actual=$(echo "$object" | yq  '.metrics.bindAddress' | tee /dev/stderr)
    [ "${actual}" = "127.0.0.1:10091" ]
   actual=$(echo "$object" | yq  '.webhook.port' | tee /dev/stderr)
    [ "${actual}" = "9091" ]
}

@test "managerConfig: configmap ( not controller_manager_config.yaml ) has defaults " {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/manager-config.yaml  \
      . | tee /dev/stderr |
      yq '.data' | tee /dev/stderr)

  local actual=$(echo "$object" | yq  '.shutdown' | tee /dev/stderr)
    [ "${actual}" = "false" ]
   actual=$(echo "$object" | yq  '.vaultTokensCleanupModel' | tee /dev/stderr)
    [ "${actual}" = "" ]
}
