{
  # modulesPath,
  ...
}:
{
  imports = [
    /*
    Configures:
    - Prevent start a tty on the serial console
    - Reboot on panic
    - Disable emergency mode
    - Disable splash image
    */
    # "${modulesPath}/profiles/headless.nix"
    /*
    Configures:
    - Available initrd kernel modules: virtio_{net,pci,mmio,blk,scsi}, 9p, 9pnet_virtio
    - Enables initrd kernel modules: virtio_{balloon,console,rng,gpu}
    */
    # "${modulesPath}/profiles/qemu-guest.nix"
  ];
}
