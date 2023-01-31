#!/usr/bin/env bats

load _helpers

@test "controller/Deployment: replicas defaults to 1" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq -rc '.[] | select(.kind == Deployment)' | tee /dev/stderr)
  echo "======================================="
  echo ${actual}
  echo "======================================="
  [ "${actual}" = "1" ]
}

@test "controller/Deployment: replicas can be set" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.controller.replicas=2' \
      . | tee /dev/stderr |
      yq -rc '.spec.replicas' | tee /dev/stderr)
  [ "${actual}" = "2" ]
}

#--------------------------------------------------------------------
# resources

@test "controller/Deployment: default resources for kubeRbacProxy" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq -rc '.spec.template.spec.containers[0].resources' | tee /dev/stderr)
  [ "${actual}" = '{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"5m","memory":"64Mi"}}' ]
}

@test "controller/Deployment: can set resources for kubeRbacProxy" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.kubeRbacProxy.resources.requests.memory=100Mi' \
      --set 'controllerManager.kubeRbacProxy.resources.requests.cpu=100m' \
      --set 'controllerManager.kubeRbacProxy.resources.limits.memory=200Mi' \
      --set 'controllerManager.kubeRbacProxy.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq -rc '.spec.template.spec.containers[0].resources' | tee /dev/stderr)
  [ "${actual}" = '{"limits":{"cpu":"200m","memory":"200Mi"},"requests":{"cpu":"100m","memory":"100Mi"}}' ]
}

@test "controller/Deployment: default resources for controller" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      . | tee /dev/stderr |
      yq -rc '.spec.template.spec.containers[1].resources' | tee /dev/stderr)
  [ "${actual}" = '{"limits":{"cpu":"500m","memory":"128Mi"},"requests":{"cpu":"10m","memory":"64Mi"}}' ]
}

@test "controller/Deployment: can set resources for controller" {
  cd `chart_dir`
  local actual=$(helm template \
      -s templates/deployment.yaml  \
      --set 'controllerManager.manager.resources.requests.memory=100Mi' \
      --set 'controllerManager.manager.resources.requests.cpu=100m' \
      --set 'controllerManager.manager.resources.limits.memory=200Mi' \
      --set 'controllerManager.manager.resources.limits.cpu=200m' \
      . | tee /dev/stderr |
      yq -rc '.spec.template.spec.containers[1].resources' | tee /dev/stderr)
  [ "${actual}" = '{"limits":{"cpu":"200m","memory":"200Mi"},"requests":{"cpu":"100m","memory":"100Mi"}}' ]
}



