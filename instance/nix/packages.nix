{
  pkgs
}:
let
  lib = pkgs.lib;

  rustToolchain = pkgs.rust-bin.stable."1.90.0".default;
  rustPlatform = pkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };

  mandatoryFeatures = [ "snp_ec2" "snp_gce" ];
  optionalFeatureSets = [
    []
    [ "debug" ]
    [ "request_certificate" ]
    [ "debug" "request_certificate" ]
  ];

  mkBundleName = mandatoryFeature: optionalFeatures:
    let
      suffix =
        if optionalFeatures == []
        then ""
        else "-${lib.concatStringsSep "-" optionalFeatures}";
    in
    "evident-bundle-${mandatoryFeature}${suffix}";

  mkRustService =
    { service
    , mandatoryFeature
    , optionalFeatures ? []
    , certificateIssuerEndpoint ? ""
    }:
    rustPlatform.buildRustPackage {
      pname = service;
      version = "0.1.0";

      src = lib.cleanSource ../.;
      cargoLock.lockFile = ../Cargo.lock;

      # Assumes each service dir has its own Cargo.toml
      buildAndTestSubdir = "services/${service}";

      buildNoDefaultFeatures = true;
      buildFeatures = [ mandatoryFeature ] ++ optionalFeatures;

      checkNoDefaultFeatures = true;
      checkFeatures = [ mandatoryFeature ] ++ optionalFeatures;

      env = {
        CERTIFICATE_ISSUER_ENDPOINT = certificateIssuerEndpoint;
      };

      nativeBuildInputs = [
        pkgs.pkg-config
        pkgs.protobuf
        pkgs.perl
      ];

      buildInputs = [
        pkgs.tpm2-tss
      ];

      meta.mainProgram = service;
    };

  mkBundle =
    { mandatoryFeature
    , optionalFeatures ? []
    , certificateIssuerEndpoint ? ""
    }:
    let
      keygen = mkRustService {
        service = "evident-keygen";
        inherit mandatoryFeature optionalFeatures;
      };

      server = mkRustService {
        service = "evident-server";
        certificateIssuerEndpoint = certificateIssuerEndpoint;
        inherit mandatoryFeature optionalFeatures;
      };
    in
    pkgs.symlinkJoin {
      name = mkBundleName mandatoryFeature optionalFeatures;
      paths = [
        keygen
        server
      ];

      meta = {
        description = "Evident bundle with both service binaries";
        mainProgram = "evident-server";
      };
    };

  matrix =
    lib.listToAttrs (
      lib.concatMap (mandatoryFeature:
        map (optionalFeatures:
          lib.nameValuePair
            (mkBundleName mandatoryFeature optionalFeatures)
            (mkBundle {
              inherit mandatoryFeature optionalFeatures;
            })
        ) optionalFeatureSets
      ) mandatoryFeatures
    );

in
{
  inherit mkBundle matrix;

  # no particular reason for this default, just need one bundle to be the default package
  default = mkBundle {
    mandatoryFeature = "snp_ec2";
    optionalFeatures = [
      "debug"
      "request_certificate"
    ];
    certificateIssuerEndpoint = "https://ca.example.com";
  };
}
