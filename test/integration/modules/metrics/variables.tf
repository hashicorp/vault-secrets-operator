# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

variable "install_kube_prometheus" {
  type    = bool
  default = false
}

variable "metrics_server_enabled" {
  type    = bool
  default = true
}