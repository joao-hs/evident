terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.19.0"
    }
    evident = {
      source = "dpss-inesc-id/evident"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = local.derived_region
  zone    = var.gcp_zone
}

provider "evident" {}
