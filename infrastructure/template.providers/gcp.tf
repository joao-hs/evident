# Copy this to file to your envs/<env> directory and adapt accordingly

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.19.0"
    }
  }
}

provider "google" {
  project = var.gcp_project
  region  = locals.derived_region
  zone    = var.gcp_zone
}
