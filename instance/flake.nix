{
  description = "Evident Rust workspace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, ... }:
  let
    system = "x86_64-linux";
    pkgs = import nixpkgs {
      inherit system;
      overlays = [ rust-overlay.overlays.default ];
    };

    evidentPackages = import ./nix/packages.nix {
      inherit pkgs;
    };
  in
  {
    packages.${system} = evidentPackages;

    apps.${system}.mkBundle = evidentPackages.mkBundle;

    nixosModules.default = import ./nix/module.nix;
  };
}
