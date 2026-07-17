{
  description = "Fleet — NixOS fleet lifecycle CLI with DAG workflow orchestration";

  # substrate.rust.tool dispatches over Cargo.gen.lock (the slim gen delta,
  # reconstructed to the full BuildSpec in pure Nix) — no crate2nix, no Cargo.nix.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.tool {
    src = ./.;
  };
}
