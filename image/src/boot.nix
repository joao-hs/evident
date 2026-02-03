{
  ...
}:

{
  boot = {
    loader = {
      grub.enable = false;
      timeout = 0;
    };

    kernelParams = [
      "console=ttyS0"
    ];

    kernelModules = [

    ];

    initrd = {
      systemd.enable = true;

      availableKernelModules = [

      ];

      kernelModules = [

      ];
    };
  };
}
