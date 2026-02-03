{
  description = "Reproducible and Immutable NixOS Images";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    evident-server = {
      url = "path:server";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };
  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "riscv64-linux"
      ];
      perSystem = { config, pkgs, ... }: {
        packages = {
          local-debug = pkgs.callPackage ./src {
            platform = "qemu";
            evidentServer = inputs.evident-server.outputs.packages.x86_64-linux.snp_mock;
          };
          gce-base = pkgs.callPackage ./src {
            platform = "gce";
            evidentServer = inputs.evident-server.outputs.packages.x86_64-linux.snp_gce;
            # withDebug = false;
          };
        };
      };
    };
}
