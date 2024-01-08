#!/usr/bin/env bats

load _helpers

#--------------------------------------------------------------------
# replicas

@test "controller/Deployment: replicas defaults to 1" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") .spec.replicas' | tee /dev/stderr)
  [ "${actual}" = "1" ]
}

@test "controller/Deployment: replicas can be set" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.replicas=2' \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") .spec.replicas' | tee /dev/stderr)
  [ "${actual}" = "2" ]
}

#--------------------------------------------------------------------
# resources

@test "controller/Deployment: default resources for kubeRbacProxy" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "kube-rbac-proxy") | .resources' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "kube-rbac-proxy") | .resources' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--max-concurrent-reconciles"])' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "controller/Deployment: maxConcurrentReconciles can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.manager.maxConcurrentReconciles=5' \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'contains(["--max-concurrent-reconciles=5"])' | tee /dev/stderr)
    [ "${actual}" = "true" ]
}

# podSecurityContext
@test "controller/Deployment: controller.podSecurityContext set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.securityContext' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'select(documentIndex == 1) | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .runAsNonRoot' | tee /dev/stderr)
   [ "${actual}" = "true" ]

   local actual=$(echo "$object" | yq 'select(documentIndex == 2) | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 2) | .runAsNonRoot' | tee /dev/stderr)
   [ "${actual}" = "true" ]
}

@test "controller/Deployment: controller.podSecurityContext can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.podSecurityContext.runAsGroup=2000' \
      --set 'controller.podSecurityContext.runAsUser=2000' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.securityContext' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'select(documentIndex == 1) | length' | tee /dev/stderr)
   [ "${actual}" = "3" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .runAsGroup' | tee /dev/stderr)
   [ "${actual}" = '2000' ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .runAsUser'| tee /dev/stderr)
   [ "${actual}" = '2000' ]

   local actual=$(echo "$object" | yq 'select(documentIndex == 2) | length' | tee /dev/stderr)
   [ "${actual}" = "3" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 2) | .runAsGroup' | tee /dev/stderr)
   [ "${actual}" = '2000' ]
   actual=$(echo "$object" | yq 'select(documentIndex == 2) | .runAsUser'| tee /dev/stderr)
   [ "${actual}" = '2000' ]
}

# securityContext
@test "controller/Deployment: controller.{manager,kube-rbac-proxy}.securityContext set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[0].securityContext.allowPrivilegeEscalation' | tee /dev/stderr)
    [ "${actual}" = "false" ]

   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[1].securityContext.allowPrivilegeEscalation' | tee /dev/stderr)
    [ "${actual}" = "false" ]

    local actual=$(echo "$object" | yq 'select(documentIndex == 2) | .containers[0].securityContext.allowPrivilegeEscalation' | tee /dev/stderr)
    [ "${actual}" = "false" ]
}

@test "controller/Deployment: controller.{manager,kube-rbac-proxy}.securityContext can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.securityContext.allowPrivilegeEscalation=true' \
      . | tee /dev/stderr |
      yq '.spec.template.spec' | tee /dev/stderr)

   local actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[0].securityContext | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[1].securityContext | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[0].securityContext.allowPrivilegeEscalation' | tee /dev/stderr)
   [ "${actual}" = 'true' ]
   actual=$(echo "$object" | yq 'select(documentIndex == 1) | .containers[1].securityContext.allowPrivilegeEscalation'| tee /dev/stderr)
   [ "${actual}" = 'true' ]

   local actual=$(echo "$object" | yq 'select(documentIndex == 2) | .containers[0].securityContext | length' | tee /dev/stderr)
   [ "${actual}" = "1" ]
   actual=$(echo "$object" | yq 'select(documentIndex == 2) | .containers[0].securityContext.allowPrivilegeEscalation' | tee /dev/stderr)
   [ "${actual}" = 'true' ]
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
# hostAliases

@test "controller/Deployment: hostAliases not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.hostAliases | select(documentIndex == 1)' | tee /dev/stderr)

  [ "${object}" = null ]
}

@test "controller/Deployment: hostAliases can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.hostAliases[0].ip=192.168.1.100' \
      --set 'controller.hostAliases[0].hostnames={vault.example.com}' \
      . | tee /dev/stderr |
      yq '.spec.template.spec.hostAliases | select(documentIndex == 1)' | tee /dev/stderr)

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

#--------------------------------------------------------------------
# affinity

@test "controller/Deployment: affinity not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq '.spec.template.spec.affinity | select(documentIndex == 1)' | tee /dev/stderr)

  [ "${object}" = null ]
}

@test "controller/Deployment: affinity can be set" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set "controller.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=topology.kubernetes.io/zone" \
      --set "controller.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].operator=In" \
      --set "controller.affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].values={antarctica-east1,antarctica-west1}" \
      . | tee /dev/stderr |
      yq '.spec.template.spec.affinity | select(documentIndex == 1)' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") .spec.template.metadata | .labels' | tee /dev/stderr)

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
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") .spec.template.metadata | .labels' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "5" ]
   actual=$(echo "$object" | yq '.label1' | tee /dev/stderr)
   [ "${actual}" = 'value1' ]
   actual=$(echo "$object" | yq '.label2'| tee /dev/stderr)
   [ "${actual}" = 'value2' ]
}

#--------------------------------------------------------------------
# extraArgs

@test "controller/Deployment: extraArgs not set by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "3" ]
}

#

@test "controller/Deployment: with extraArgs" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controller.manager.extraArgs={--foo=baz,--bar=qux}'  \
      . | tee /dev/stderr |
      yq 'select(.kind == "Deployment" and .metadata.labels."control-plane" == "controller-manager") | .spec.template.spec.containers[] | select(.name == "manager") | .args' | tee /dev/stderr)

   local actual=$(echo "$object" | yq '. | length' | tee /dev/stderr)
   [ "${actual}" = "5" ]

   local actual=$(echo "$object" | yq '.[3]' | tee /dev/stderr)
   [ "${actual}" = "--foo=baz" ]
   local actual=$(echo "$object" | yq '.[4]' | tee /dev/stderr)
   [ "${actual}" = "--bar=qux" ]
}


#--------------------------------------------------------------------
# pre-delete-controller

@test "controller/Deployment: pre-delete-controller Job name is not truncated by default" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq 'select(.kind == "Job") | .metadata' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '.name' | tee /dev/stderr)
  [ "${actual}" = "pdcc-release-name-vault-secrets-operator" ]
}

@test "controller/Deployment: pre-delete-controller Job name is truncated to 63 characters" {
  cd `chart_dir`
  local object=$(helm template \
      -s templates/deployment.yaml  \
      --set fullnameOverride=abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz \
      . | tee /dev/stderr |
      yq 'select(.kind == "Job") | .metadata' | tee /dev/stderr)

  local actual=$(echo "$object" | yq '.name' | tee /dev/stderr)
  [ "${actual}" = "pdcc-abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdef" ]
  [ "${#actual}" -eq 63 ]
}