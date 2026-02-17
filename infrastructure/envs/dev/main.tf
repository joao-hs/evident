locals {
  gce_vm_types = {
    base = {
      image_id = var.gce_image_base_id
      count    = var.gce_base_count
    }
  }
}

module "gce_base" {
  source = "../../modules/gce-simple"

  name_prefix = "base"

  machine_type = var.gcp_machine_type
  zone         = var.gcp_zone

  image_id  = local.gce_vm_types.base.image_id
  count_vms = local.gce_vm_types.base.count

  labels = {
    vm_type = "base"
    env     = "dev"
  }
}
