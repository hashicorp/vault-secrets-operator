resource "helm_release" "argo_rollouts" {
  namespace        = "argo"
  create_namespace = true
  name             = "argo-rollouts"
  repository       = "https://argoproj.github.io/argo-helm"
  chart            = "argo-rollouts"
}