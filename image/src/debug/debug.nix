{
  pkgs,
  ...
}:
{
  services.openssh = {
    enable = true;
    settings = {
      PermitRootLogin = "prohibit-password";
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
    };
  };

  environment.systemPackages = with pkgs; [
    tpm2-tools
    binutils
    lsof
    # for the rust server debugging
    evcxr
    rustup
    gcc
    pkg-config
    protobuf
    perl
    gdbHostCpuOnly
  ];

  # TODO: Offer SSH host keys, otherwise, we lose reproducibility

  networking.firewall.allowedTCPPorts = [
    22
    5001
  ];

  users.users.root = {
    shell = pkgs.bashInteractive;
    openssh.authorizedKeys.keys = [
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIINMEdCzfidRGxp1xtwGidvqwPMdQAwB3uRTclL771iM evident-owner"
    ];
  };
}
