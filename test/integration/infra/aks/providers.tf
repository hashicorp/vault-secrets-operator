terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "3.53.0"
    }
  }

  required_version = "~> 1.3"
}

provider "azurerm" {
  features {}
}