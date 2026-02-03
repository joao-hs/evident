{
  description = "Evident-server: Lightweight attester server for the Evident framework";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ { nixpkgs, rust-overlay, ... }:
  let
    system = "x86_64-linux";
    overlays = [ inputs.rust-overlay.overlays.default ];
    pkgs = import inputs.nixpkgs {
      inherit system overlays;
    };

    rustToolchain = pkgs.rust-bin.stable."1.90.0".default;

    mkPackage = { buildFeatures ? [] }: pkgs.rustPlatform.buildRustPackage {
      pname = "evident-server";
      version = "0.1.0";

      src = pkgs.lib.cleanSource ./.;
      cargoLock.lockFile = ./Cargo.lock;

      toolchain = rustToolchain;

      buildFeatures = buildFeatures;

      nativeBuildInputs = [
        pkgs.pkg-config
        pkgs.protobuf
        pkgs.perl
      ];
      buildInputs = [
        pkgs.tpm2-tss
      ];
    };
  in
  {
    packages.${system} = {
      default = mkPackage { buildFeatures = [ "snp_mock" ]; };
      snp_ec2 = mkPackage { buildFeatures = [ "snp_ec2" ]; };
      snp_avm = mkPackage { buildFeatures = [ "snp_avm" ]; };
      snp_gce = mkPackage { buildFeatures = [ "snp_gce" ]; };
      snp_qemu_vmpl0 = mkPackage { buildFeatures = [ "snp_qemu" "qemu_vmpl0" ]; };
      snp_qemu_vmpl1 = mkPackage { buildFeatures = [ "snp_qemu" "qemu_vmpl1" ]; };
      snp_qemu_vmpl2 = mkPackage { buildFeatures = [ "snp_qemu" "qemu_vmpl2" ]; };
      snp_qemu_vmpl3 = mkPackage { buildFeatures = [ "snp_qemu" "qemu_vmpl3" ]; };
    };
  };
}
