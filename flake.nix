{
  description = "Fleet — NixOS fleet lifecycle CLI with DAG workflow orchestration";

  nixConfig = {
    allow-import-from-derivation = true;
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.11";
    crate2nix.url = "github:nix-community/crate2nix";
    flake-utils.url = "github:numtide/flake-utils";
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devenv = {
      url = "github:cachix/devenv";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # gen is wired BOTH as a build-time IFD tool (substrate
    # auto-regen pipeline) AND as a runtime-PATH tool (fleet's
    # `rebuild` shells out to `gen fleet-sweep` before invoking
    # darwin-rebuild / nixos-rebuild). The `runtimeNeedsGen = true`
    # consumer flag below tells substrate to wrap the fleet binary
    # so its runtime PATH begins with THIS flake.lock's gen — never
    # /etc/profiles' activation-time gen, which is the very thing
    # `nix run .#rebuild` is trying to activate. Closes the
    # bootstrap loop where pre-activation sweeps would call the
    # stale pre-activation gen.
    gen = {
      url = "github:pleme-io/gen";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    crate2nix,
    flake-utils,
    substrate,
    devenv,
    gen,
  }:
    (import "${substrate}/lib/rust-tool-release-flake.nix" {
      inherit nixpkgs crate2nix flake-utils devenv gen;
    }) {
      toolName = "fleet";
      src = self;
      repo = "pleme-io/fleet";
      runtimeNeedsGen = true;
    };
}
