resource "google_compute_firewall" "evident-server" {
  name    = "${var.name_prefix}-evident-server-rules"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["5000-5010"] # TODO: squeeze to the actually needed port(s)
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = [local.network_firewall_rules_name]
}
