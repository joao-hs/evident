variable "name_prefix" {
  description = "Prefix for instance names, e.g. worker-a"
  type        = string
}

variable "machine_type" {
  description = "GCE machine type"
  type        = string
}

variable "zone" {
  description = "GCE zone to deploy into"
  type        = string
}

variable "image_id" {
  description = "ID of base VM image type"
  type        = string
}

variable "count_vms" {
  description = "Number of VMs to create for this image type"
  type        = number
  default     = 0
}

variable "labels" {
  description = "Instance labels"
  type        = map(string)
  default     = {}
}

locals {
  # "debug" suffix until TODO(s) in network.tf are resolved
  network_firewall_rules_name = "${var.name_prefix}-evident-server-debug"
}
