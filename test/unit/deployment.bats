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

@test "controller/Deployment: default resources for controller and job" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.' | tee /dev/stderr)

   local controller=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "manager") | .resources' | tee /dev/stderr)
   local job=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "pre-delete-controller-cleanup") | .resources' | tee /dev/stderr)

   local actual=$(echo "$controller" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "10m" ]
   actual=$(echo "$controller" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   actual=$(echo "$controller" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   actual=$(echo "$controller" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "128Mi" ]
   local actual=$(echo "$job" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "10m" ]
   actual=$(echo "$job" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "64Mi" ]
   actual=$(echo "$job" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "500m" ]
   actual=$(echo "$job" | yq '.limits.memory' | tee /dev/stderr)
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
      yq '.' | tee /dev/stderr)

   local controller=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "manager") | .resources' | tee /dev/stderr)
   local job=$(echo "$object" | yq '.spec.template.spec.containers[] | select(.name == "pre-delete-controller-cleanup") | .resources' | tee /dev/stderr)

   local actual=$(echo "$controller" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   actual=$(echo "$controller" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   actual=$(echo "$controller" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   actual=$(echo "$controller" | yq '.limits.memory' | tee /dev/stderr)
    [ "${actual}" = "200Mi" ]
   actual=$(echo "$job" | yq '.requests.cpu' | tee /dev/stderr)
    [ "${actual}" = "100m" ]
   actual=$(echo "$job" | yq '.requests.memory' | tee /dev/stderr)
    [ "${actual}" = "100Mi" ]
   actual=$(echo "$job" | yq '.limits.cpu' | tee /dev/stderr)
    [ "${actual}" = "200m" ]
   actual=$(echo "$job" | yq '.limits.memory' | tee /dev/stderr)
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

# kubernetesClusterDomain
@test "controller/Deployment: controller.kubernetesClusterDomain not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.containers[0].env | map(select(.name == "KUBERNETES_CLUSTER_DOMAIN")) | .[] .value' | tee /dev/stderr)
    [ "${actual}" = "cluster.local" ]

   actual=$(echo "$object" | yq '.containers[1].env | map(select(.name == "KUBERNETES_CLUSTER_DOMAIN")) | .[] .value' | tee /dev/stderr)
    [ "${actual}" = "cluster.local" ]
}

@test "controller/Deployment: controller.kubernetesClusterDomain can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.kubernetesClusterDomain=foo.bar' \
      . | tee /dev/stderr |
      yq '.spec.template.spec | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '.containers[0].env | map(select(.name == "KUBERNETES_CLUSTER_DOMAIN")) | .[] .value' | tee /dev/stderr)
    [ "${actual}" = "foo.bar" ]

   actual=$(echo "$object" | yq '.containers[1].env | map(select(.name == "KUBERNETES_CLUSTER_DOMAIN")) | .[] .value' | tee /dev/stderr)
    [ "${actual}" = "foo.bar" ]
}

#--------------------------------------------------------------------
# annotations

@test "controller/Deployment: annotations not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.metadata.annotations | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq '."kubectl.kubernetes.io/default-container"' | tee /dev/stderr)
   [ "${actual}" = "manager" ]
}

@test "controller/Deployment: annotations can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.annotations.annot1=value1' \
      --set 'controller.annotations.annot2=value2' \
      . | tee /dev/stderr |
      yq '.spec.template.metadata.annotations | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "3" ]
   actual=$(echo "$object" | yq '."kubectl.kubernetes.io/default-container"' | tee /dev/stderr)
   [ "${actual}" = 'manager' ]
   actual=$(echo "$object" | yq '.annot1' | tee /dev/stderr)
   [ "${actual}" = 'value1' ]
   actual=$(echo "$object" | yq '.annot2'| tee /dev/stderr)
   [ "${actual}" = 'value2' ]
}

#--------------------------------------------------------------------
# terminationGracePeriodSeconds

@test "controller/Deployment: default terminationGracePeriodSeconds when revokeClientCacheOnUninstall is false by default" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.terminationGracePeriodSeconds | select(documentIndex == 1)' | tee /dev/stderr)
   [ "${actual}" = "120" ]
}

#--------------------------------------------------------------------
# preDeleteHookTimeoutSeconds

@test "controller/Deployment: default preDeleteHookTimeoutSeconds when revokeClientCacheOnUninstall is false by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.containers[0].args | select(documentIndex == 2)' | tee /dev/stderr)

  local actual=$(echo "$object" | yq 'contains(["--pre-delete-hook-timeout-seconds=120"])' | tee /dev/stderr)
  [ "${actual}" = "true" ]
}

#--------------------------------------------------------------------
# controller.imagePullSecrets

@test "controller/Deployment: no image pull secrets by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '. | select(documentIndex == 0)' | tee /dev/stderr)

  local actual=$(echo "$object" |
      yq -r '.imagePullSecrets | length > 0' | tee /dev/stderr)
  [ "${actual}" = "false" ]
}

@test "controller/Deployment: Custom imagePullSecrets - string array" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.imagePullSecrets[0]=foo' \
      --set 'controller.imagePullSecrets[1]=bar' \
      . | tee /dev/stderr |
      yq '. | select(documentIndex == 0)' | tee /dev/stderr)

  local actual=$(echo "$object" |
      yq -r '.imagePullSecrets | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[0] | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[1] | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" |
     yq -r '.imagePullSecrets[0].name' | tee /dev/stderr)
  [ "${actual}" = "foo" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[1].name' | tee /dev/stderr)
  [ "${actual}" = "bar" ]
}

@test "controller/Deployment: Custom imagePullSecrets - map" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.imagePullSecrets[0].name=foo' \
      --set 'controller.imagePullSecrets[1].name=bar' \
      . | tee /dev/stderr |
      yq '. | select(documentIndex == 0)' | tee /dev/stderr)

  local actual=$(echo "$object" |
      yq -r '.imagePullSecrets | length' | tee /dev/stderr)
  [ "${actual}" = "2" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[0] | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[1] | length' | tee /dev/stderr)
  [ "${actual}" = "1" ]
  actual=$(echo "$object" |
     yq -r '.imagePullSecrets[0].name' | tee /dev/stderr)
  [ "${actual}" = "foo" ]
  actual=$(echo "$object" |
      yq -r '.imagePullSecrets[1].name' | tee /dev/stderr)
  [ "${actual}" = "bar" ]
}

#--------------------------------------------------------------------
# nodeSelector

@test "controller/Deployment: nodeSelector not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.nodeSelector | select(documentIndex == 1)' | tee /dev/stderr)

   [ "${object}" = null ]
}

@test "controller/Deployment: nodeSelector can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.nodeSelector.key1=value1' \
      --set 'controller.nodeSelector.key2=value2' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.nodeSelector | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "2" ]
   actual=$(echo "$object" | yq '.key1' | tee /dev/stderr)
   [ "${actual}" = 'value1' ]
   actual=$(echo "$object" | yq '.key2' | tee /dev/stderr)
   [ "${actual}" = 'value2' ]
}

#--------------------------------------------------------------------
# tolerations

@test "controller/Deployment: tolerations not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.tolerations | select(documentIndex == 1)' | tee /dev/stderr)

  [ "${object}" = null ]
}

@test "controller/Deployment: tolerations can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.tolerations[0].key=key1' \
      --set 'controller.tolerations[0].operator=Equal' \
      --set 'controller.tolerations[0].value=value1' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.tolerations | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = '1' ]
   actual=$(echo "$object" | yq '.[0] | length' | tee /dev/stderr)
   [ "${actual}" = '3' ]
   actual=$(echo "$object" | yq '.[0].key' | tee /dev/stderr)
   [ "${actual}" = 'key1' ]
   actual=$(echo "$object" | yq '.[0].operator' | tee /dev/stderr)
   [ "${actual}" = 'Equal' ]
   actual=$(echo "$object" | yq '.[0].value' | tee /dev/stderr)
   [ "${actual}" = 'value1' ]
}

#--------------------------------------------------------------------
# extraEnv values

@test "controller/Deployment: extra env string aren't set by default" {
    cd `chart_dir`
    local object=$(helm template  \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |  \
      yq '.spec.template.spec.containers[1].env | select(documentIndex == 1)' |  \
      tee /dev/stderr)

    local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '3' ]
}

@test "controller/Deployment: extra env string values can be set" {
    cd `chart_dir`
    local object=$(helm template  \
      -s templates/deployment.yaml  \
      --set 'controller.manager.extraEnv[0].name=HTTP_PROXY'  \
      --set 'controller.manager.extraEnv[0].value=http://proxy.example.com/'  \
      . | tee /dev/stderr |  \
      yq '.spec.template.spec.containers[1].env | select(documentIndex == 1)' |  \
      tee /dev/stderr)

    local actual=$(echo "$object" | yq '.[3].name' | tee /dev/stderr)
    [ "${actual}" = 'HTTP_PROXY' ]
    actual=$(echo "$object" | yq '.[3].value' | tee /dev/stderr)
    [ "${actual}" = 'http://proxy.example.com/' ]
    actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '4' ]
}

@test "controller/Deployment: extra env number values can be set" {
    cd `chart_dir`
    local object=$(helm template  \
      -s templates/deployment.yaml  \
      --set 'controller.manager.extraEnv[0].name=RANDOM_PORT'  \
      --set 'controller.manager.extraEnv[0].value=42'  \
      . | tee /dev/stderr |  \
      yq '.spec.template.spec.containers[1].env | select(documentIndex == 1)' |  \
      tee /dev/stderr)

    local actual=$(echo "$object" | yq '.[3].name' | tee /dev/stderr)
    [ "${actual}" = 'RANDOM_PORT' ]
    actual=$(echo "$object" | yq '.[3].value' | tee /dev/stderr)
    [ "${actual}" = '42' ]
    actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '4' ]
}

@test "controller/Deployment: extra env values don't get double quoted" {
    cd `chart_dir`
    local object=$(printf  \
      'controller: {manager: {extraEnv: [{name: QUOTED_ENV, value: "noquotesneeded"}]}}\n' |  \
      helm template -s templates/deployment.yaml --values /dev/stdin . |   \
      tee /dev/stderr |  \
      yq '.spec.template.spec.containers[1].env | select(documentIndex == 1)' |  \
      tee /dev/stderr)

    local actual=$(echo "$object" | yq '.[3].name' | tee /dev/stderr)
    [ "${actual}" = 'QUOTED_ENV' ]
    actual=$(echo "$object" | yq '.[3].value' | tee /dev/stderr)
    [ "${actual}" = 'noquotesneeded' ]
    actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '4' ]
}

@test "controller/Deployment: extra env values with white space" {
    cd `chart_dir`
    local object=$(helm template  \
      -s templates/deployment.yaml  \
      --set 'controller.manager.extraEnv[0].name=WHITESPACE_WORKS'  \
      --set 'controller.manager.extraEnv[0].value=Hello World!'  \
      . | tee /dev/stderr |  \
      yq '.spec.template.spec.containers[1].env | select(documentIndex == 1)' |  \
      tee /dev/stderr)

    local actual=$(echo "$object" | yq '.[3].name' | tee /dev/stderr)
    [ "${actual}" = 'WHITESPACE_WORKS' ]
    actual=$(echo "$object" | yq '.[3].value' | tee /dev/stderr)
    [ "${actual}" = 'Hello World!' ]
    actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
    [ "${actual}" = '4' ]
}

#--------------------------------------------------------------------
# extraLabels

@test "controller/Deployment: extraLabels not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.metadata.labels | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "3" ]
}

@test "controller/Deployment: extraLabels can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.extraLabels.label1=value1' \
      --set 'controller.extraLabels.label2=value2' \
      . | tee /dev/stderr |
      yq '.spec.template.metadata.labels | select(documentIndex == 1)' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "5" ]
   actual=$(echo "$object" | yq '.label1' | tee /dev/stderr)
   [ "${actual}" = 'value1' ]
   actual=$(echo "$object" | yq '.label2'| tee /dev/stderr)
   [ "${actual}" = 'value2' ]
}
