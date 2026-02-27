{
  ...
}:

{
  # source: https://docs.aws.amazon.com/vm-import/latest/userguide/prepare-vm-image.html
  # General configurations:
  # - Disable any antivirus or intrusion detection software on your VM. 
  # These services can be re-enabled after the import process is complete.
  # - Uninstall the VMware Tools from your VMware VM.
  # - Disconnect any CD-ROM drives (virtual or physical).
  # - Your source VM must have a functional DHCP client service. Ensure that the
  # service can start and is not disabled administratively. All static IP 
  # addresses currently assigned to the source VM are removed during import. 
  # When your imported instance is launched in an Amazon VPC, it receives a 
  # primary private IP address from the IPv4 address range of the subnet. If you
  # don't specify a primary private IP address when you launch the instance, we 
  # select an available IP address in the subnet's IPv4 range for you. For more 
  # information, see [VPC and Subnet Sizing](https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Subnets.html#VPC_Sizing).

  # Linux/Unix configurations:
  # - Enable Secure Shell (SSH) for remote access.
  # - Make sure that your host firewall (such as Linux iptables) allows access 
  # to SSH. Otherwise, you won't be able to access your instance after the 
  # import is complete.
  # - Make sure that you have configured a non-root user to use public key-based
  # SSH to access your instance after it is imported. The use of password-based 
  # SSH and root login over SSH are both possible, but not recommended. The use 
  # of public keys and a non-root user is recommended because it is more secure.
  # VM Import does not configure an ec2-user account as part of the import 
  # process.
  # - Make sure that your Linux VM uses GRUB (GRUB legacy) or GRUB 2 as its 
  # bootloader.
  # - Make sure that your Linux VM uses one of the following for the root file 
  # system: EXT2, EXT3, EXT4, Btrfs, JFS, or XFS.
  # - Make sure that your Linux VM is not using predictable network interface 
  # device names.
  # - Shut down your VM before exporting it from your virtualization environment.


}