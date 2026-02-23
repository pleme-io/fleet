{
  description = "Fleet — NixOS fleet lifecycle CLI with DAG workflow orchestration";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      fleet = (import ./Cargo.nix {inherit pkgs;}).rootCrate.build;
    in {
      packages.default = fleet;
      packages.fleet = fleet;
    })
    // {
      overlays.default = final: prev: {
        fleet = self.packages.${prev.system}.default;
      };
    };
}
