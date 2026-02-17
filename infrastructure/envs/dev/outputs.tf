output "vm_ips" {
  # TODO: merge with others with prettier prints
  value = module.gce_base.instance_IPv4s
}
