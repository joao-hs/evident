{
  description = "Evident Go application (reproducible build on nixpkgs-unstable)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;

        pname = "evident";
        version = "0.1.0";

        app = pkgs.buildGoModule {
          inherit pname version;
          # from client/flake.nix
          src = ../.;
          modRoot = "client";
          subPackages = [ "." ];

          vendorHash = "sha256-5IUK1I8bDmY/xmKytoU5Isav24yBQM5Tb7c2wvFa8k4=";

          nativeBuildInputs = with pkgs; [
              buf
              protobuf
              protoc-gen-go
              protoc-gen-go-grpc
            ];

          env = {
            CGO_ENABLED = "0";
          };

          preBuild = ''
            export GOFLAGS="$GOFLAGS -trimpath -buildvcs=false"
            export PATH="${pkgs.protoc-gen-go}/bin:${pkgs.protoc-gen-go-grpc}/bin:$PATH"

            buf generate
          '';

          postInstall = ''
            if [ -x "$out/bin/client" ]; then
              mv "$out/bin/client" "$out/bin/evident"
            fi
          '';

          ldflags = [
            "-s"
            "-w"
            "-buildid="
          ];

          tags = [ ];
        };
      in
      {
        packages = {
          default = app;
          ${pname} = app;
        };

        apps.default = {
          type = "app";
          program = "${app}/bin/evident";
        };
      });
}
