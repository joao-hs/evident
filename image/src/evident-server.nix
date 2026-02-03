{
  evidentServer,
  ...
}:

let
  evidentPort = 5000;
in
{
  # users.groups.evident = {};

  # users.users.evidents = {
  #   enable = true;
  #   isSystemUser = true;
  #   group = "evident";
  #   extraGroups = [ "wheel" ];
  #   shell = "${pkgs.util-linux}/bin/nologin";
  #   packages = [
  #     evidentServer.packages.x86_64-linux.default
  #   ];
  # };

  users.users.root = {
    packages = [
      evidentServer
    ];
  };

  systemd.services.evident-server = {
    description = "Evident Server";
    after = [ "network.target" ];
    wantedBy = [ "multi-user.target" ];

    serviceConfig = {
      ExecStart = "${evidentServer}/bin/evident-server --port ${builtins.toString evidentPort}";
      User = "root";
      # Group = "evident";
      Restart = "on-failure";
      RestartSec = "5s";
    };
  };

  networking.firewall.allowedTCPPorts = [
    evidentPort
  ];
}
