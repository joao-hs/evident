variable "name_prefix" {
  description = "Prefix for instance names, e.g. worker-a"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "image_id" {
  description = "AMI ID"
  type        = string
}

variable "count_vms" {
  description = "Number of instances to create"
  type        = number
  default     = 0
}

variable "labels" {
  description = "Instance tags (key-value pairs)"
  type        = map(string)
  default     = {}
}