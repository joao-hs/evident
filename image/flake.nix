{
  description = "Reproducible and Immutable NixOS Images";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    evident-instance = {
      url = "path:instance";
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
        packages =
        let
          mkBundle = inputs.evident-instance.apps.x86_64-linux.mkBundle;
        in
        {
          gce-profiling = pkgs.callPackage ./src {
            platform = "gce";
            inherit inputs;
            evidentInstancePackage = mkBundle {
              mandatoryFeature = "snp_gce";
              optionalFeatures = [ "debug" ];
              certificateIssuerEndpoint = "evident-ca.joaohs.com:5010";
            };
            withDebug = true;
            withProfiling = true;
          };
          gce-base = pkgs.callPackage ./src {
            platform = "gce";
            inherit inputs;
            evidentInstancePackage = mkBundle {
              mandatoryFeature = "snp_gce";
              optionalFeatures = [
                "debug"
                # "request_certificate"
              ];
              certificateIssuerEndpoint = "evident-ca.joaohs.com:5010";
            };
            withDebug = true;
          };
          ec2-profiling = pkgs.callPackage ./src {
            platform = "ec2";
            inherit inputs;
            evidentInstancePackage = mkBundle {
              mandatoryFeature = "snp_ec2";
              optionalFeatures = [ "debug" ];
              certificateIssuerEndpoint = "evident-ca.joaohs.com:5010";
            };
            withDebug = true;
            withProfiling = true;
          };
          ec2-base = pkgs.callPackage ./src {
            platform = "ec2";
            inputs = inputs;
            evidentInstancePackage = mkBundle {
              mandatoryFeature = "snp_ec2";
              optionalFeatures = [
                "debug"
                # "request_certificate"
              ];
              certificateIssuerEndpoint = "evident-ca.joaohs.com:5010";
            };
            withDebug = true;
            withProfiling = true;
          };
        };
      };
    };
}
