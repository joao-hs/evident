{
  pkgs,
  modulesPath,
  lib,
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
    "${modulesPath}/profiles/headless.nix"
  ];

  environment.systemPackages = with pkgs; [
    cryptsetup
    openssl # TODO: verify if needed
    tpm2-tss # TODO: verify if needed
  ];

  # Prevent anyone from logging in:
  # (1/5)
  users.users.root = lib.mkDefault {
    hashedPassword = "!";
    shell = pkgs.nologin;
  };
  users.allowNoPasswordLogin = true;

  # (2/5)
  services.getty.autologinUser = lib.mkDefault null;

  # (3/5)
  console.enable = lib.mkDefault false;

  # (4/5)
  services.openssh.enable = lib.mkDefault false;

  # (5/5)
  users.mutableUsers = false;

  security = {
    # lockKernelModules = true;
    protectKernelImage = true;
  };

  systemd.coredump = {
    enable = true; # use systemd-coredump
    # disable coredumps
    extraConfig = ''
      Storage=none
      ProcessSizeMax=0
    '';
  };

  system = {
    # Disable in-place upgrades, we're immutable!
    switch.enable = false;
    stateVersion = "25.11";
  };
}
