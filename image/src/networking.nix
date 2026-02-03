{
  lib,
  ...
}:

{
  # General

  ## Disable topology based interface names: we just need one - eth0
  networking.usePredictableInterfaceNames = false;

  ## Hostname
  networking.hostName = lib.mkDefault "base";

  ## Firewall - iptables (allowed ports should be defined close to service's configuration)
  networking.firewall = {
    enable = true;
    allowPing = true;
  };

  # Option 1: Use systemd.networkd
  /*
  # Use systemd-resolved.
  services.resolved.enable = true;

  # Use systemd-networkd in the main system..
  systemd.network.enable = true;
  networking.useNetworkd = true;
  # ..disable networkmanager..
  networking.networkmanager.enable = false;
  # ..and the system DHCP.
  networking.useDHCP = false;


  systemd.network.networks."10-wired" = {
    matchConfig.Name = "eth0";
    networkConfig.DHCP = "yes";
  };
  */

}
