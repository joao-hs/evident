#output "all_vm_ips" {
#  # TODO: merge with others with prettier prints
#  value = module.gce_base.instance_IPv4s
#}

output "attestation_result" {
  value = merge(evident_attest.attestation.attestation_results)
}
