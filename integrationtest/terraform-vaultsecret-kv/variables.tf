variable "k8s_test_namespace" {
  default = "testing"
}

variable "k8s_vault_namespace" {
  default = "demo"
}

variable "k8s_config_context" {
  default = "kind-kind"
}

variable "k8s_config_path" {
  default = "~/.kube/config"
}

variable "vault_kv_mount_path" {
  default = "kvv2"
}
