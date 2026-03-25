# fleet — Node lifecycle CLI with DAG workflow orchestration

NixOS fleet management + infrastructure orchestration via declarative DAG workflows.

## Build

```bash
cargo build
cargo test   # 12 tests
```

## Architecture

```
src/
  main.rs              # CLI entry point (clap)
  config.rs            # FleetConfig, ActionDef, PangeaOperation, StepResult
  dag.rs               # Kahn's algorithm — topological sort into parallel levels
  flow.rs              # Flow validation, cycle detection (DFS coloring)
  commands/
    flow.rs            # flow list / flow run — DAG execution + output accumulation
    pangea.rs          # Pangea action handler — subprocess + tofu output capture
    deploy.rs          # NixOS deploy via deploy-rs
    build.rs           # Nix build
    diff.rs            # Closure diff
    status.rs          # Node status
    ping.rs            # SSH connectivity
    reboot.rs          # Node reboot
    rollback.rs        # NixOS rollback
    rebuild.rs         # darwin-rebuild / nixos-rebuild
    exec.rs            # Remote command execution
    ssh.rs             # Interactive SSH
    utils.rs           # Logging, SSH helpers, command runners
  registry.rs          # Node registry (FLEET_NODES JSON)
  targeting.rs         # Node targeting (@tag, names, --all)
  hooks.rs             # Pre/post hooks
  secrets.rs           # 1Password secret provisioning
```

## Scope: Fleet vs Pangea

Fleet and Pangea are complementary tools with distinct responsibilities:

```
┌─────────────────────────────────────────────────────────────┐
│  Pangea = IaC lifecycle                                     │
│    Template compilation → Terraform JSON → plan/apply       │
│    State boundaries (one template = one .tfstate)            │
│    Multi-template DAG (planned: DependencyManager + TSort)  │
│    Output passing via terraform_remote_state                 │
└───────────────────────────┬─────────────────────────────────┘
                            │ pangea plan/apply (subprocess)
┌───────────────────────────▼─────────────────────────────────┐
│  Fleet = Deployment lifecycle                               │
│    NixOS node management (build, deploy, rollback, reboot)  │
│    DAG workflow orchestration (flows with depends_on)        │
│    Can invoke pangea as one action type in a larger flow    │
│    SSH, hooks, secrets, node targeting                       │
└─────────────────────────────────────────────────────────────┘
```

**Fleet's Pangea action type** bridges the two: `type: pangea` in a flow step
calls `pangea plan/apply` as a subprocess. After apply, captures outputs via
`tofu output -json` for downstream step interpolation.

**When to use what:**
- Pure IaC (templates only) → `pangea plan/apply`
- NixOS deployment → `fleet deploy`
- Mixed workflows (IaC + deploy) → Fleet flow with Pangea steps + deploy steps

## Action Types

| Type | Purpose | Needs nodes? |
|------|---------|:---:|
| `deploy` | NixOS deploy via deploy-rs | Yes |
| `build` | Nix build without activating | Yes |
| `diff` | Closure diff | Yes |
| `status` | Node status | Yes |
| `ping` | SSH connectivity | Yes |
| `rollback` | NixOS rollback | Yes |
| `reboot` | Node reboot | Yes |
| `exec` | Remote command | Yes |
| `shell` | Local shell command | No |
| `darwin-rebuild` | macOS rebuild | No |
| `home-manager-rebuild` | HM rebuild | No |
| `flake-update` | Nix flake update | No |
| **`pangea`** | **Pangea IaC operation** | **No** |

## Pangea Action

```yaml
flows:
  deploy-infra:
    steps:
      - id: permissions
        action:
          type: pangea
          file: k3s_permissions.rb
          namespace: development
          operation: apply        # plan | apply | destroy | output | synth
      - id: cluster
        action:
          type: pangea
          file: k3s_cluster.rb
          namespace: development
          operation: apply
          env:
            ROLE_ARN: "${permissions.node_role_arn}"
        depends_on: [permissions]
```

**Output interpolation:** `${step_id.output_name}` resolves from captured
`tofu output -json` values of upstream steps.

## DAG System

Flows define steps with `depends_on` lists. Kahn's algorithm produces
parallel execution levels:

```
Level 1: [permissions]           # no deps
Level 2: [network, storage]      # depend on permissions (parallel)
Level 3: [compute]               # depends on network + storage
```

Cycle detection via DFS coloring (Gray→Gray edge = cycle).

## Conventions

- Edition 2021, serde_yaml_ng for YAML, serde_json for outputs
- Node registry optional for Pangea-only flows (falls back to empty)
- `fleet.yaml` loaded from flake root (walks up to find `flake.nix`)
- `fleet.yaml` is always regenerated before flow execution (never stale)
- `--dry-run` prints execution plan without running

## Synth Operation

The `synth` operation compiles Pangea templates to Terraform JSON without
running `tofu plan/apply`. Useful for validating template output in CI or
inspecting generated JSON. Added alongside plan/apply/destroy/output as a
first-class Pangea operation.
