# Fleet

NixOS fleet lifecycle CLI with DAG workflow orchestration.

Fleet manages NixOS machines — deploy, build, diff, status, rollback, reboot — with
tag-based targeting and composable multi-step workflows defined in YAML.

## Install

```bash
# Nix flake
nix run github:pleme-io/fleet

# Or add as a flake input
fleet = {
  url = "github:pleme-io/fleet";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

## Quick start

Fleet reads its node registry from the `FLEET_NODES` environment variable (JSON).
The typical setup is a Nix wrapper that injects this at runtime:

```nix
fleet-wrapped = pkgs.writeShellScript "fleet" ''
  export FLEET_NODES='${builtins.toJSON nodeRegistry}'
  export FLEET_FLAKE_DIR="$(git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")"
  exec ${fleet}/bin/fleet "$@"
'';
```

The node registry is a JSON object:

```json
{
  "web1": { "hostname": "10.0.0.1", "ssh_user": "root", "system": "x86_64-linux", "tags": ["production", "k3s"] },
  "web2": { "hostname": "10.0.0.2", "ssh_user": "root", "system": "x86_64-linux", "tags": ["production", "k3s"] },
  "staging": { "hostname": "10.0.0.10", "ssh_user": "root", "system": "x86_64-linux", "tags": ["staging"] }
}
```

## Commands

```
fleet deploy <targets>     Deploy NixOS configurations (deploy-rs / colmena)
fleet build <targets>      Build without activating
fleet diff <targets>       Show closure diff (current vs. new)
fleet status [targets]     Show generation, uptime, kernel, NixOS version
fleet ping [targets]       Check SSH connectivity
fleet exec <targets> -- <cmd>  Run command on remote nodes
fleet rollback <targets>   Rollback to previous generation
fleet reboot <targets>     Reboot nodes
fleet ssh <node>           Open interactive SSH session
fleet info                 Print node registry
fleet flow list            List defined workflows
fleet flow run <name>      Execute a workflow
```

### Targeting

Targets can be node names, `@tag` selectors, or `--all`:

```bash
fleet deploy web1                # single node (uses deploy-rs)
fleet deploy web1 web2           # multiple nodes (uses colmena)
fleet deploy @production         # all nodes tagged "production"
fleet status --all               # every node in the registry
fleet exec @k3s -- kubectl get nodes
```

## Configuration

Fleet reads `fleet.yaml` from `FLEET_FLAKE_DIR` (or the current directory). All sections
are optional.

```yaml
# Global SSH defaults
ssh:
  connect_timeout: 5
  strict_host_key: accept-new
  options:
    ServerAliveInterval: "60"
    ServerAliveCountMax: "3"

# Deploy defaults
deploy:
  show_trace: false
  magic_rollback: true

# Per-node overrides
nodes:
  bastion:
    ssh:
      connect_timeout: 15
      options:
        ProxyJump: "jump.example.com"

# Lifecycle hooks
hooks:
  deploy:
    pre: "echo 'deploying $FLEET_NODE'"
    post: "echo 'deployed $FLEET_NODE'"
  build:
    pre: "git diff --quiet HEAD || echo 'WARNING: uncommitted changes'"
```

### Hooks

Hooks run shell commands before (`pre`) and after (`post`) fleet operations. Available
for: `deploy`, `build`, `diff`, `exec`, `rollback`, `reboot`.

- **Pre-hooks** abort the operation on failure.
- **Post-hooks** warn but continue.

Environment variables set during hook execution:

| Variable | Description |
|----------|-------------|
| `FLEET_NODE` | Node name |
| `FLEET_HOST` | Hostname |
| `FLEET_USER` | SSH user |

## Flows

Flows are named DAG workflows defined in `fleet.yaml`. Steps declare dependencies and
fleet resolves them into topological execution levels.

```yaml
flows:
  deploy-cluster:
    description: "Build, diff, then rolling deploy with health checks"
    steps:
      - id: build
        action: { type: build, show_trace: true }
        targets: [server, agent]

      - id: diff
        action: { type: diff }
        targets: [server, agent]
        depends_on: [build]

      - id: confirm
        action:
          type: shell
          command: |
            echo "Review the diff above. Press enter or Ctrl-C to abort."
            read
        depends_on: [diff]

      - id: deploy-server
        action: { type: deploy }
        targets: [server]
        depends_on: [confirm]

      - id: health-check
        action:
          type: shell
          command: "ssh root@server kubectl get nodes >/dev/null && echo 'healthy'"
        depends_on: [deploy-server]

      - id: deploy-agent
        action: { type: deploy }
        targets: [agent]
        depends_on: [health-check]
```

### Action types

| Type | Description |
|------|-------------|
| `build` | `nix build` / `colmena build` |
| `deploy` | deploy-rs / `colmena apply` |
| `diff` | Closure diff (current vs. new) |
| `status` | Node status |
| `ping` | SSH connectivity check |
| `exec` | Remote command (`command: ["systemctl", "status"]`) |
| `shell` | Local shell command (`command: "echo hello"`) |
| `rollback` | Rollback NixOS generation |
| `reboot` | Reboot nodes |
| `darwin-rebuild` | Run `nix run .#darwin-rebuild` |
| `home-manager-rebuild` | Run `nix run .#home-manager-rebuild` |
| `flake-update` | Run `nix flake update` (optional `inputs: [...]`) |

### Dry-run

Preview the execution plan without running anything:

```bash
fleet flow run deploy-cluster --dry-run
```

```
Execution plan (dry-run):

  Level 1:
    build [build] targets: server, agent
  Level 2:
    diff [diff] targets: server, agent
      depends_on: build
  Level 3:
    confirm [shell] targets: (inherit CLI targets)
      depends_on: diff
  Level 4:
    deploy-server [deploy] targets: server
      depends_on: confirm
  Level 5:
    health-check [shell] targets: (inherit CLI targets)
      depends_on: deploy-server
  Level 6:
    deploy-agent [deploy] targets: agent
      depends_on: health-check
```

### Conditions

Steps can have a `condition` — a shell command that must succeed for the step to execute.
If the condition fails, the step is skipped.

```yaml
- id: deploy-canary
  action: { type: deploy }
  targets: [canary]
  condition:
    command: "test -f .canary-enabled"
  depends_on: [build]
```

## Backend tools

Fleet dispatches to existing NixOS deployment tools:

- **Single node** — [deploy-rs](https://github.com/serokell/deploy-rs) (magic rollback)
- **Multiple nodes** — [colmena](https://github.com/zhaofengli/colmena) (parallel apply)
- **Diff** — `nix store diff-closures`
- **Build** — `nix build` / `colmena build`

These must be on `PATH` when fleet runs. The Nix wrapper typically handles this.

## License

MIT
