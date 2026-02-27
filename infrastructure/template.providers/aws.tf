# Copy this to file to your envs/<env> directory and adapt accordingly

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.34.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}