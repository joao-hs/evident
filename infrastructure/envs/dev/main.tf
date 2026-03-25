locals {
  gce_vm_types = {
    base = {
      image_id = local.gce_image_base_id
      count    = var.gce_base_count
    }
  }
  ec2_vm_types = {
    base = {
      image_id = data.aws_ami.base.id
      count    = var.ec2_base_count
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

module "ec2_base" {
  source = "../../modules/ec2-simple"

  name_prefix = "base"

  instance_type = var.aws_instance_type

  image_id  = local.ec2_vm_types.base.image_id
  count_vms = local.ec2_vm_types.base.count

  labels = {
    vm_type = "base"
    env     = "dev"
  }
}
