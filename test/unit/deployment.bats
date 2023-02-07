#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# replicas

@test "controller/Deployment: replicas defaults to 1" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.replicas | select(documentIndex == 1)' | tee /dev/stderr)
  [ "${actual}" = "1" ]
}

@test "controller/Deployment: replicas can be set" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.replicas=2' \
      . | tee /dev/stderr |
      yq '.spec.replicas | select(documentIndex == 1)' | tee /dev/stderr)
  [ "${actual}" = "2" ]
}

#--------------------------------------------------------------------
# resources

@test "controller/Deployment: default resources for kubeRbacProxy" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[0].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "5m" ]
   local actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   local actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   local actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "128Mi" ]
}

@test "controller/Deployment: can set resources for kubeRbacProxy" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.kubeRbacProxy.resources.requests.memory=100Mi' \
      --set 'controllerManager.kubeRbacProxy.resources.requests.cpu=100m' \
      --set 'controllerManager.kubeRbacProxy.resources.limits.memory=200Mi' \
      --set 'controllerManager.kubeRbacProxy.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[0].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   local actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   local actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   local actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "200Mi" ]
}

@test "controller/Deployment: default resources for controller" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "10m" ]
   local actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   local actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   local actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "128Mi" ]
}

@test "controller/Deployment: can set resources for controller" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.manager.resources.requests.memory=100Mi' \
      --set 'controllerManager.manager.resources.requests.cpu=100m' \
      --set 'controllerManager.manager.resources.limits.memory=200Mi' \
      --set 'controllerManager.manager.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   local actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   local actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   local actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "200Mi" ]
}



