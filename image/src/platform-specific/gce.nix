{
  pkgs,
  lib,
  modulesPath,
  ...
}:

{
  # REQUIREMENTS:
  # 1. Boot disk no larger than 2048 GB
  # 2. The boot disk must have a functional MBR partition table or a hybrid
  #  configuration of a GPT partition table with an MBR bootloader.
  # 3. The primary partition on the boot disk can be in any format that you
  #  like as long as it boots properly from the MBR bootloader.
  # 4. The bootloader on the boot disk must not have quiet, rhgb, or
  #  splashimage= kernel command-line arguments. Compute Engine does not
  #  support splash screens on startup. You can remove these values from
  #  the GRUB config during the bootloader configuration step.
  # 5. The operating system on the boot disk must support ACPI.
  # 6. Perform a consistency check on the disk image by using the qemu-img
  #  check command on the disk.
  # 7. The disk image filename must be disk.raw.
  # 8. The RAW image file must have a size in an increment of 1 GB. For
  #  example, the file must be either 10 GB or 11 GB but not 10.5 GB.
  # 9. The compressed file must be a .tar.gz file that uses gzip compression
  #  and the --format=oldgnu option for the tar utility (manual).
  # 10? Add console=ttyS0,38400n8d to the kernel command-line arguments, so
  #  that the instance can interact with the Serial Console.
  # 11? Edit the /etc/fstab file and remove references to all disks and
  #  partitions other than the boot disk itself and partitions on that boot
  #  disk. Invalid entries in /etc/fstab can cause your system startup process
  #  to stop.
  # 12. Enable the kernel options:
  #  12.1.  CONFIG_KVM_GUEST=y
  #  12.2.  !CONFIG_KVM_CLOCK=y
  #  12.3.  CONFIG_VIRTIO_PCI=y
  #  12.4.  !CONFIG_SCSI_VIRTIO=y
  #  12.5.  CONFIG_VIRTIO_NET=y
  #  12.6.  CONFIG_PCI_MSI=y
  #  12.7.  CONFIG_AMD_MEM_ENCRYPT=y            (AMD SEV-SNP support)
  #  12.8.  CONFIG_GVE=y                        (AMD SEV-SNP and Intel TDX support)
  #  12.9.  CONFIG_NET_VENDOR_GOOGLE=y          (AMD SEV-SNP and Intel TDX support)
  #  12.10. CONFIG_PCI_MSI=y                    (AMD SEV-SNP and Intel TDX support)
  #  12.11. CONFIG_SWIOTLB=y                    (AMD SEV-SNP and Intel TDX support)
  #  12.12. CONFIG_STRICT_DEVMEM=y              (optional)
  #  12.13. CONFIG_DEVKMEM=n                    (optional)
  #  12.14. CONFIG_DEFAULT_MMAP_MIN_ADDR=65536  (optional)
  #  12.15. CONFIG_DEBUG_RODATA=y               (optional)
  #  12.16. CONFIG_DEBUG_SET_MODULE_RONX=y      (optional)
  #  12.17. CONFIG_CC_STACKPROTECTOR=y          (optional)
  #  12.18. CONFIG_COMPAT_VDSO=n                (optional)
  #  12.19. CONFIG_COMPAT_BRK=n                 (optional)
  #  12.20. CONFIG_X86_PAE=y                    (optional)
  #  12.21. CONFIG_SYN_COOKIES=y                (optional)
  #  12.22. CONFIG_SECURITY_YAMA=y              (optional)
  #  12.23. CONFIG_SECURITY_YAMA_STACKED=y      (optional)
  # 13. Further hardening recommendations, add the lines to `/etc/sysctl.conf`:
  #  13.1.  net.ipv4.tcp_syncookies = 1
  #  13.2.  net.ipv4.conf.all.accept_source_route = 0
  #  13.3.  net.ipv4.conf.default.accept_source_route = 0
  #  13.4.  net.ipv4.conf.all.accept_redirects = 0
  #  13.5.  net.ipv4.conf.default.accept_redirects = 0
  #  13.6.  net.ipv4.conf.all.secure_redirects = 1
  #  13.7.  net.ipv4.conf.default.secure_redirects = 1
  #  13.8.  net.ipv4.ip_forward = 0
  #  13.9.  net.ipv4.conf.all.send_redirects = 0
  #  13.10. net.ipv4.conf.default.send_redirects = 0
  #  13.11. net.ipv4.conf.all.rp_filter = 1
  #  13.12. net.ipv4.conf.default.rp_filter = 1
  #  13.13. net.ipv4.icmp_echo_ignore_broadcasts = 1
  #  13.14. net.ipv4.icmp_ignore_bogus_error_responses = 1
  #  13.15. net.ipv4.conf.all.log_martians = 1
  #  13.16. net.ipv4.conf.default.log_martians = 1
  #  13.17. kernel.randomize_va_space = 2
  #  13.18. fs.protected_hardlinks=1
  #  13.19. fs.protected_symlinks=1
  #  13.20. kernel.kptr_restrict=1
  #  13.21. kernel.yama.ptrace_scope=1
  #  13.22. kernel.perf_event_paranoid=2
  # 14. Kernel must be version >=6.1 LTS (AMD SEV-SNP support) or  >=6.6 (Intel TDX support)
  # 15. Google Cloud Image flags, `--guest-os-features`:
  #  15.1. SEV_CAPABLE | SEV_LIVE_MIGRATABLE_V2 | SEV_SNP_CAPABLE | TDX_CAPABALE
  #  15.2. GVNIC
  #  15.3. UEFI_COMPATIBLE
  #  15.4. VIRTIO_SCSI_MULTIQUEUE
  # Sources:
  # - https://docs.cloud.google.com/compute/docs/import/import-existing-image
  # - https://docs.cloud.google.com/compute/docs/images/building-custom-os
  # - https://docs.cloud.google.com/compute/docs/images/create-custom
  # - https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/create-custom-confidential-vm-images

  # boot.kernelPatches = {
  #   structuredExtraConfig = {
  #     # attrset of extra configuration parameters without the CONFIG_ prefix
  #     # values should generally be lib.kernel.yes, lib.kernel.no or lib.kernel.module
  #   };
  #   features = {
  #     # attrset of extra "features" the kernel is considered to have
  #     # (may be checked by other NixOS modules, optional)
  #   };
  # };

  # boot.kernelPatches = [
  #   {
  #     name = "gce-required-options";
  #     patch = null;
  #     structuredExtraConfig = {
  #       KVM_GUEST = lib.kernel.yes;
  #       VIRTIO_PCI = lib.kernel.yes;
  #       VIRTIO_NET = lib.kernel.yes;
  #       PCI_MSI = lib.kernel.yes;
  #     };
  #   }
  #   {
  #     name = "gce-snp-required";
  #     patch = null;
  #     structuredExtraConfig = {
  #       AMD_MEM_ENCRYPT = lib.kernel.yes;
  #       GVE = lib.kernel.yes;
  #       NET_VENDOR_GOOGLE = lib.kernel.yes;
  #       SWIOTLB = lib.kernel.yes;
  #     };
  #   }
  # ];

  # boot.kernel.sysctl = {
  #   "net.ipv4.tcp_syncookies" = 1;
  #   # ...
  # };

  # boot.extraModprobeConfig = ''
  #   options
  # '';

  /*
  DEFAULT KERNEL OPTIONS:
  No Change Needed:
  CONFIG_KVM_GUEST=y
  CONFIG_PCI_MSI=y
  CONFIG_AMD_MEM_ENCRYPT=y
  CONFIG_NET_VENDOR_GOOGLE=y
  CONFIG_PCI_MSI=y
  CONFIG_SWIOTLB=y
  (optionals)
  CONFIG_STRICT_DEVMEM=y
  CONFIG_DEFAULT_MMAP_MIN_ADDR=65536
  CONFIG_SYN_COOKIES=y
  CONFIG_SECURITY_YAMA=y

  * Change Needed:
  * CONFIG_VIRTIO_PCI=m -> y
  * CONFIG_SCSI_VIRTIO=m -> y
  * CONFIG_VIRTIO_NET=m -> y
  * CONFIG_GVE=m -> y

  ! Missing:
  ! CONFIG_KVM_CLOCK=y
  ! (optionals)
  ! CONFIG_DEVKMEM=n
  ! CONFIG_DEBUG_RODATA=y
  ! CONFIG_DEBUG_SET_MODULE_RONX=y
  ! CONFIG_CC_STACKPROTECTOR=y
  ! CONFIG_COMPAT_VDSO=n
  ! CONFIG_COMPAT_BRK=n
  ! CONFIG_X86_PAE=y
  ! CONFIG_SECURITY_YAMA_STACKED=y
  */

  imports = [
    /*
    Configures:
    - Available initrd kernel modules: virtio_{net,pci,mmio,blk,scsi}, 9p, 9pnet_virtio
    - Enables initrd kernel modules: virtio_{balloon,console,rng,gpu}
    */
    "${modulesPath}/profiles/qemu-guest.nix"
  ];

  boot.kernelParams = [
    "console=ttyS0"
    "panic=1"
    "boot.panic_on_fail"
  ];
  boot.initrd.kernelModules = [ "virtio_scsi" ];
  boot.kernelModules = [
    "virtio_pci"
    "virtio_net"
    "gve" # for gVNIC support
  ];

  services.udev.packages = [ pkgs.google-guest-configs ];
  services.udev.path = [ pkgs.google-guest-configs ];

  networking.extraHosts = ''
    169.254.169.254 metadata.google.internal metadata
  '';

  networking.timeServers = [ "metadata.google.internal" ];

  networking.interfaces.eth0.mtu = 1460;

  boot.extraModprobeConfig = lib.readFile "${pkgs.google-guest-configs}/etc/modprobe.d/gce-blacklist.conf";

  environment.etc."sysctl.d/60-gce-network-security.conf".source =
    "${pkgs.google-guest-configs}/etc/sysctl.d/60-gce-network-security.conf";

  # environment.etc."systemd/resolved.conf.d/gce-resolved.conf".source =
  #   "${pkgs.google-guest-configs}/etc/systemd/resolved.conf.d/gce-resolved.conf";


  # environment.etc."default/instance_configs.cfg".text = ''
  #   [Accounts]
  #   useradd_cmd = useradd -m -s /run/current-system/sw/bin/bash -p * {user}

  #   [Daemons]
  #   accounts_daemon = ${lib.boolToString config.users.mutableUsers}

  #   [InstanceSetup]
  #   set_host_keys = false

  #   [MetadataScripts]
  #   default_shell = ${pkgs.stdenv.shell}

  #   [NetworkInterfaces]
  #   dhclient_script = ${pkgs.google-guest-configs}/bin/google-dhclient-script
  #   setup = false
  # '';

  # boot.kernelModules = [
  #   "virtio_pci"
  #   "virtio_scsi"
  #   "virtio_net"
  #   "gve"
  # ];
}
