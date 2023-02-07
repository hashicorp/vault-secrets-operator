#helm repo update
#helm install \
#--wait \
#--version 39.6.0 \
#prometheus prometheus-community/kube-prometheus-stack

resource "helm_release" "kube-prometheus" {
  count            = 0
  namespace        = "kube-prometheus"
  name             = "kube-prometheus"
  create_namespace = true
  wait             = true
  wait_for_jobs    = true
  repository       = "prometheus-community"
  chart            = "kube-prometheus-stack"
  version          = "39.6.0"
}
