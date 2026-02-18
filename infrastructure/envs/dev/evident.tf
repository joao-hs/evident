locals {
  standard_evident_server_port = 5000
}

resource "evident_attest" "attestation" {
  machine_type  = var.gcp_machine_type
  endpoints     = { for ip in module.gce_base.instance_IPv4s : ip => local.standard_evident_server_port }
  expected_pcrs = file("${path.module}/artifacts/demo.pcrs")
}
