variable "gcp_project" {
  type = string
}

variable "gcp_region" {
  # according to gcp_zone
  type        = string
  description = "Optional GCP region. If null, it will be derived from the zone."
  default     = null
}

variable "gcp_zone" {
  description = "Choose from https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations#supported-zones"
  type        = string
  default     = "europe-west3-a"
}

locals {
  # If gcp_region is provided, use it.
  # Otherwise, strip the last two characters from the zone (e.g., 'us-central1-a' becomes 'us-central1')
  derived_region = var.gcp_region != null ? var.gcp_region : join("-", slice(split("-", var.gcp_zone), 0, 2))
}

variable "gcp_machine_type" {
  description = "Choose from https://cloud.google.com/compute/docs/general-purpose-machines#n2d_machine_types"
  type        = string
  default     = "n2d-standard-2"
}

variable "gce_image_base_id" {
  description = "ID of base VM image type"
  type        = string
}

variable "gce_base_count" {
  description = "Number of VMs to launch of type base on GCE"
  type        = number
  default     = 1
}
