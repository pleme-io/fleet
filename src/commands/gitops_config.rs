use std::path::Path;

use serde_yaml_ng::Value;

pub const PATH: &str = "/etc/pleme-gitops/config.yaml";

pub const DEFAULT_BUILD_TIMEOUT_SECONDS: u64 = 90 * 60;

pub fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn parse(gitops_config: &str) -> Option<Value> {
    serde_yaml_ng::from_str(gitops_config).ok()
}

pub fn activation_lock_of(gitops_config: &str) -> Option<String> {
    let v = parse(gitops_config)?;
    let lock = v.get("switch_lock")?;
    if lock.get("hold").and_then(Value::as_bool) != Some(false) {
        return None;
    }
    lock.get("path")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .filter(|p| !p.is_empty())
}

pub fn build_timeout_seconds_of(gitops_config: Option<&str>) -> u64 {
    gitops_config
        .and_then(parse)
        .and_then(|v| v.get("build_timeout_seconds").and_then(Value::as_u64))
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_BUILD_TIMEOUT_SECONDS)
}

pub fn build_timeout_seconds() -> u64 {
    build_timeout_seconds_of(read(Path::new(PATH)).as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_budget_is_the_configured_build_timeout() {
        let ryn = r#"{"build_timeout_seconds":5400,"poll_seconds":60,"switch_lock":{"hold":false,"path":"/var/run/pleme-activation.lock"}}"#;
        assert_eq!(build_timeout_seconds_of(Some(ryn)), 5400);
        assert_eq!(
            build_timeout_seconds_of(Some("build_timeout_seconds: 7200\n")),
            7200
        );
    }

    #[test]
    fn an_unset_or_disabled_build_timeout_is_sentinelas_default() {
        assert_eq!(
            build_timeout_seconds_of(None),
            DEFAULT_BUILD_TIMEOUT_SECONDS
        );
        assert_eq!(
            build_timeout_seconds_of(Some("poll_seconds: 60\n")),
            DEFAULT_BUILD_TIMEOUT_SECONDS
        );
        assert_eq!(
            build_timeout_seconds_of(Some("build_timeout_seconds: 0\n")),
            DEFAULT_BUILD_TIMEOUT_SECONDS
        );
        assert_eq!(
            build_timeout_seconds_of(Some(": not yaml [")),
            DEFAULT_BUILD_TIMEOUT_SECONDS
        );
    }
}
