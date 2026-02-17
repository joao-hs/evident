output "instance_IPv4s" {
  value = [for i in google_compute_instance.this : i.network_interface.0.access_config.0.nat_ip]
}
