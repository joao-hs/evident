resource "google_compute_instance" "this" {
  count        = var.count_vms
  name         = "${var.name_prefix}-${count.index}"
  machine_type = var.machine_type
  zone         = var.zone

  boot_disk {
    auto_delete = true
    initialize_params {
      image = var.image_id
    }
  }

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false

  network_interface {
    network = "default"

    stack_type = "IPV4_ONLY" # TODO: check if needed

    access_config {
      // needed for CVMs:
      network_tier = "PREMIUM"
    }
    // needed for CVMs:
    nic_type = "GVNIC"
  }

  scheduling {
    // CMV migration isn't supported yet
    on_host_maintenance = "TERMINATE"
  }

  # TODO abstract
  min_cpu_platform = "AMD Milan"
  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "SEV_SNP"
  }

  shielded_instance_config {
    enable_integrity_monitoring = false
    enable_secure_boot          = false
    enable_vtpm                 = true
  }

  tags   = [local.network_firewall_rules_name]
  labels = var.labels
}
