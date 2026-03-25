# output "attestation_result" {
#   value = merge(evident_attest.attestation.attestation_results)
# }

output "ec2_public_ips" {
  value = module.ec2_base.instance_IPv4s
}

output "gce_public_ips" {
  value = module.gce_base.instance_IPv4s
}
