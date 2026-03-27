{
  lib,
  config,
  ...
}:
let
  cfg = config.services.evident;
in
{
  options.services.evident = {
    enable = lib.mkEnableOption "Evident services";

    package = lib.mkOption {
      type = lib.types.package;
      description = "Bundle package containing evident-keygen and evident-server.";
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "root";
      description = "User account for both Evident services.";
    };

    keygen.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable evident-keygen.";
    };

    server.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable evident-server.";
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.evident-keygen = lib.mkIf cfg.keygen.enable {
      description = "Instance Key Generation";
      after = [ "local-fs.target" ];
      wantedBy = [ "multi-user.target" ];

      unitConfig = {
        DefaultDependencies = false;
      };

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/evident-keygen";
        UMask = "0077";
        User = cfg.user;
      };
    };

    systemd.services.evident-server = lib.mkIf cfg.server.enable {
      description = "Evident Attester Server";
      after = [
        "network-online.target"
        "nss-lookup.target"
        "evident-keygen.service"
      ];
      requires = [ "evident-keygen.service" ];
      wants = [
        "network-online.target"
        "nss-lookup.target"
      ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/evident-server";
        Restart = "on-failure";
        RestartSec = "5s";
        TimeoutStartSec = "300s";
        CPUAffinity = "0";
        MemoryMax = "256M";
        User = cfg.user;
      };
    };
  };
}
