{
  # evidentServer,
  inputs,
  evidentInstancePackage,
  ...
}:

let
  evidentPort = 5000;
in
{
  # users.users.root = {
  #   packages = [
  #     evidentServer
  #   ];
  # };

  # systemd.services.evident-server = {
  #   description = "Evident Server";
  #   after = [ "network.target" ];
  #   wantedBy = [ "multi-user.target" ];

  #   serviceConfig = {
  #     ExecStart = "${evidentServer}/bin/evident-server --port ${builtins.toString evidentPort}";
  #     User = "root";
  #     # Group = "evident";
  #     Restart = "on-failure";
  #     RestartSec = "5s";
  #   };
  # };

  imports = [
    inputs.evident-instance.nixosModules.default
  ];

  services.evident = {
    enable = true;
    package = evidentInstancePackage;
    user = "root";
    # TODO: make the port configurable via the module option (passes it as argument to the server binary)
  };

  networking.firewall.allowedTCPPorts = [
    evidentPort
  ];
}
