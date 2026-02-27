terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.34.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 7.19.0"
    }
    evident = {
      source = "dpss-inesc-id/evident"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

provider "google" {
  project = var.gcp_project
  region  = local.gcp_region
  zone    = var.gcp_zone
}

provider "evident" {}
