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
      --set 'controller.replicas=2' \
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
   actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "128Mi" ]
}

@test "controller/Deployment: can set resources for kubeRbacProxy" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.kubeRbacProxy.resources.requests.memory=100Mi' \
      --set 'controller.kubeRbacProxy.resources.requests.cpu=100m' \
      --set 'controller.kubeRbacProxy.resources.limits.memory=200Mi' \
      --set 'controller.kubeRbacProxy.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[0].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
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
   actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "128Mi" ]
}

@test "controller/Deployment: can set resources for controller" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.manager.resources.requests.memory=100Mi' \
      --set 'controller.manager.resources.requests.cpu=100m' \
      --set 'controller.manager.resources.limits.memory=200Mi' \
      --set 'controller.manager.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].resources | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   actual=$(echo "$object" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   actual=$(echo "$object" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   actual=$(echo "$object" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "200Mi" ]
}

#--------------------------------------------------------------------
# clientCache

@test "controller/Deployment: clientCache not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].args | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--client-cache"])' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "controller/Deployment: clientCache settings can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.manager.clientCache.cacheSize=22' \
      --set 'controller.manager.clientCache.persistenceModel=direct-encrypted' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].args | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--client-cache-size=22", "--client-cache-persistence-model=direct-encrypted"])' | tee /dev/stderr)
    [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# maxConcurrentReconciles

@test "controller/Deployment: maxConcurrentReconciles not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].args | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--max-concurrent-reconciles-vds"])' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "controller/Deployment: maxConcurrentReconciles can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.manager.maxConcurrentReconciles=5' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[1].args | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--max-concurrent-reconciles-vds=5"])' | tee /dev/stderr)
    [ "${actual}" = "true" ]
}


