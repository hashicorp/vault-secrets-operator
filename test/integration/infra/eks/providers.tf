# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: BUSL-1.1

terraform {

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.49.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "3.6.1"
    }
  }

  required_version = "~> 1.3"
}

provider "aws" {
  region = var.region
}
