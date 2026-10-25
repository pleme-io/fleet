//! Which engine evaluates and drives this rebuild.
//!
//! The node's configuration says, not fleet: pleme-io/nix publishes
//! `<class>Configurations.<node>.config.pleme.buildEngine.driver`
//! (`modules/pleme/shared/build-engine.nix`) as
//! `{ engine, program, argvPrefix, flakeRefSyntax }`. fleet reads it before it
//! builds anything and runs that driver.
//!
//! CppNix is the default in every case that is not an explicit selection:
//! a flake that predates `driver` (the attribute is absent), a probe that
//! fails, or `FLEET_BUILD_ENGINE=cppnix`. CppNix is the oracle and the daemon
//! either way, and its own evaluation reports any real error with a better
//! message than the probe would.

use anyhow::{bail, Result};
use serde::Deserialize;
use std::path::Path;

/// The configuration family a node lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemClass {
    Nixos,
    Darwin,
}

impl SystemClass {
    fn attr_prefix(self) -> &'static str {
        match self {
            Self::Nixos => "nixosConfigurations",
            Self::Darwin => "darwinConfigurations",
        }
    }
}

/// `pleme.buildEngine.driver`, as the nix module renders it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Driver {
    pub engine: String,
    pub program: Option<String>,
    pub argv_prefix: Vec<String>,
    pub flake_ref_syntax: String,
}

/// The engine this rebuild runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Engine {
    /// `nixos-rebuild` / `darwin-rebuild`: today's path, unchanged.
    CppNix,
    /// `sui system rebuild`, from the selected registry entry.
    Sui {
        program: String,
        argv_prefix: Vec<String>,
    },
}

/// What the probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    Found(String),
    /// The flake has no `pleme.buildEngine.driver` for this node.
    Absent,
    Failed(String),
}

/// `FLEET_BUILD_ENGINE`: `auto` (unset) reads the node's selection;
/// `cppnix` skips the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Override {
    Auto,
    CppNix,
}

pub fn parse_override(value: Option<&str>) -> Result<Override> {
    match value.map(str::trim) {
        None | Some("") | Some("auto") => Ok(Override::Auto),
        Some("cppnix") => Ok(Override::CppNix),
        Some(other) => bail!(
            "FLEET_BUILD_ENGINE={other} is not one of auto, cppnix; \
             selecting another engine is the node's `pleme.buildEngine.selected`"
        ),
    }
}

/// `nix` arguments that read the node's driver.
pub fn probe_args(class: SystemClass, node: &str) -> Vec<String> {
    vec![
        "eval".into(),
        "--json".into(),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
        format!(
            ".#{}.{node}.config.pleme.buildEngine.driver",
            class.attr_prefix()
        ),
    ]
}

/// `nix build` of the node's selected engine package, so a store-path driver exists before it runs.
pub fn realize_args(class: SystemClass, node: &str) -> Vec<String> {
    vec![
        "build".into(),
        "--no-link".into(),
        "--extra-experimental-features".into(),
        "nix-command flakes".into(),
        format!(
            ".#{}.{node}.config.pleme.buildEngine.package",
            class.attr_prefix()
        ),
    ]
}

/// Sort a finished probe into found, absent or failed.
pub fn classify(success: bool, stdout: &str, stderr: &str) -> ProbeOutcome {
    if success {
        return ProbeOutcome::Found(stdout.trim().to_string());
    }
    // Only a missing `buildEngine`/`driver` is "absent"; a missing node is a
    // real failure and must not read as a flake that predates the surface.
    let absent = [
        "attribute 'driver' missing",
        "attribute 'buildEngine' missing",
    ]
    .iter()
    .any(|m| stderr.contains(m));
    if absent {
        ProbeOutcome::Absent
    } else {
        ProbeOutcome::Failed(stderr.trim().to_string())
    }
}

/// The engine for a probe outcome. `Err` only for a selection fleet does not
/// know how to drive, which is a disagreement between fleet and the registry.
pub fn select(outcome: &ProbeOutcome) -> Result<Engine> {
    let json = match outcome {
        ProbeOutcome::Found(json) => json,
        ProbeOutcome::Absent | ProbeOutcome::Failed(_) => return Ok(Engine::CppNix),
    };
    let driver: Driver = serde_json::from_str(json)
        .map_err(|e| anyhow::anyhow!("pleme.buildEngine.driver is not the expected shape: {e}"))?;
    match driver.engine.as_str() {
        "cppnix" => Ok(Engine::CppNix),
        "sui" => match driver.program {
            Some(program) => Ok(Engine::Sui {
                program,
                argv_prefix: driver.argv_prefix,
            }),
            None => bail!("pleme.buildEngine selects sui but names no driver for this class"),
        },
        other => bail!("pleme.buildEngine selects `{other}`, which fleet cannot drive"),
    }
}

/// argv (after `sudo`) for a sui rebuild. sui takes only a local flake path,
/// so the flake is always the checkout's absolute path.
pub fn sui_argv(
    program: &str,
    argv_prefix: &[String],
    flake_root: &Path,
    node: &str,
) -> Vec<String> {
    let mut argv = vec![program.to_string()];
    argv.extend(argv_prefix.iter().cloned());
    argv.push("switch".into());
    argv.push("--flake".into());
    argv.push(format!("{}#{node}", flake_root.display()));
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUI_DRIVER: &str = r#"{"argvPrefix":["system","rebuild"],"engine":"sui","flakeRefSyntax":"local-path-only","program":"/run/current-system/sw/bin/sui"}"#;
    const CPPNIX_DRIVER: &str = r#"{"argvPrefix":[],"engine":"cppnix","flakeRefSyntax":"remote","program":"/run/current-system/sw/bin/nixos-rebuild"}"#;

    #[test]
    fn probe_reads_the_nodes_driver() {
        assert_eq!(
            probe_args(SystemClass::Nixos, "plo").last().unwrap(),
            ".#nixosConfigurations.plo.config.pleme.buildEngine.driver"
        );
        assert_eq!(
            probe_args(SystemClass::Darwin, "ryn").last().unwrap(),
            ".#darwinConfigurations.ryn.config.pleme.buildEngine.driver"
        );
    }

    #[test]
    fn realize_builds_the_nodes_selected_engine_package() {
        let args = realize_args(SystemClass::Darwin, "cid");
        assert_eq!(args.first().unwrap(), "build");
        assert!(args.contains(&"--no-link".to_string()));
        assert_eq!(
            args.last().unwrap(),
            ".#darwinConfigurations.cid.config.pleme.buildEngine.package"
        );
    }

    #[test]
    fn cppnix_is_the_default() {
        assert_eq!(
            select(&ProbeOutcome::Found(CPPNIX_DRIVER.into())).unwrap(),
            Engine::CppNix
        );
        assert_eq!(select(&ProbeOutcome::Absent).unwrap(), Engine::CppNix);
        assert_eq!(
            select(&ProbeOutcome::Failed("boom".into())).unwrap(),
            Engine::CppNix
        );
        assert_eq!(parse_override(None).unwrap(), Override::Auto);
        assert_eq!(parse_override(Some("cppnix")).unwrap(), Override::CppNix);
        assert!(
            parse_override(Some("sui")).is_err(),
            "sui is selected by the node, not the env"
        );
    }

    #[test]
    fn a_sui_selection_drives_sui() {
        let engine = select(&ProbeOutcome::Found(SUI_DRIVER.into())).unwrap();
        let Engine::Sui {
            program,
            argv_prefix,
        } = engine
        else {
            panic!("{engine:?}")
        };
        assert_eq!(
            sui_argv(&program, &argv_prefix, Path::new("/home/luis/nix"), "zek"),
            [
                "/run/current-system/sw/bin/sui",
                "system",
                "rebuild",
                "switch",
                "--flake",
                "/home/luis/nix#zek"
            ]
        );
    }

    #[test]
    fn unknown_or_driverless_selection_is_refused() {
        let unknown =
            r#"{"argvPrefix":[],"engine":"lix","flakeRefSyntax":"remote","program":"/x"}"#;
        assert!(select(&ProbeOutcome::Found(unknown.into())).is_err());
        let driverless =
            r#"{"argvPrefix":[],"engine":"sui","flakeRefSyntax":"local-path-only","program":null}"#;
        assert!(select(&ProbeOutcome::Found(driverless.into())).is_err());
    }

    #[test]
    fn only_a_missing_surface_is_absent() {
        assert_eq!(
            classify(false, "", "error: attribute 'driver' missing\n at …"),
            ProbeOutcome::Absent
        );
        assert_eq!(
            classify(false, "", "error: attribute 'buildEngine' missing"),
            ProbeOutcome::Absent
        );
        assert!(matches!(
            classify(
                false,
                "",
                "error: flake 'x' does not provide attribute 'nixosConfigurations.nope'"
            ),
            ProbeOutcome::Failed(_)
        ));
        assert_eq!(classify(true, "{}\n", ""), ProbeOutcome::Found("{}".into()));
    }
}
