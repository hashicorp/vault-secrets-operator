resource "helm_release" "kube-prometheus" {
  namespace        = "kube-prometheus"
  name             = "kube-prometheus"
  create_namespace = true
  wait             = true
  wait_for_jobs    = true
  repository       = "https://prometheus-community.github.io/helm-charts"
  chart            = "kube-prometheus-stack"
  version          = "39.6.0"
}
