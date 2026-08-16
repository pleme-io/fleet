//! GitHub token resolution for `fleet rebuild`.
//!
//! ## Why this module exists
//!
//! The pleme-io `nix` flake has ~160 PRIVATE inputs, so nix's fetcher cannot
//! evaluate it at all without a GitHub credential. Steady state, the node has
//! one: a successful activation renders it from SOPS into an `!include` in
//! nix.conf (`profiles/nixos-pleme-base/default.nix`), and every later rebuild
//! authenticates on its own.
//!
//! The failure mode this module closes is that the credential can be MISSING
//! or STALE while every file that should carry it is still present — a node
//! that has never activated, or one whose `/run/secrets` froze because it
//! could not rebuild (the stale-token cascade in `nodes/rio/CLAUDE.md`).
//!
//! ## ★ THE SYMPTOM IS USUALLY 404, NOT 401 — measured 2026-08-16
//!
//! This is the diagnostic that costs the most time, because 404 reads as "that
//! commit is gone" and sends you hunting a bad pin instead of a bad
//! credential. GitHub answers a private repo with **404, not 403**, so it does
//! not leak the repo's existence — and the codeload tarball endpoint every
//! flake input goes through cannot distinguish *no* token from *wrong* token:
//!
//! | request                          | codeload tarball |
//! |----------------------------------|------------------|
//! | private repo, no token           | **404**          |
//! | private repo, wrong/expired token| **404**          |
//! | private repo, good token         | 302              |
//! | public repo, any token state     | 302              |
//!
//! So a real failure looks like this, and the commit named in it exists fine:
//!
//! ```text
//! error: unable to download 'https://github.com/pleme-io/ensaio/archive/<rev>.tar.gz':
//!        HTTP error 404
//! ```
//!
//! `401 Bad credentials` DOES occur, but on the other path — `api.github.com`,
//! which nix uses to resolve a ref to a rev — and only when a token is present
//! and rejected. Seeing 401 therefore means "a token is being sent and it is
//! wrong"; seeing 404 on a private input means "no usable token is being sent"
//! and says nothing about whether the rev exists.
//!
//! Verify which you have with the rev from the error, rather than guessing:
//!
//! ```text
//! curl -so /dev/null -w '%{http_code}\n' https://github.com/<owner>/<repo>/archive/<rev>.tar.gz
//! curl -so /dev/null -w '%{http_code}\n' -H "Authorization: token $TOK" <same URL>
//! ```
//!
//! 404 then 302 is this module's problem. 404 then 404 is a genuinely missing
//! rev.
//!
//! So: resolve a token from the first source that actually YIELDS one, and if
//! none of the on-disk ones do, scrape SOPS directly.
//!
//! ## The four defects this replaces (measured 2026-08-15 against v0.1.18)
//!
//! 1. **The old gate was file EXISTENCE, not token presence** — `netrc_path
//!    .exists() && access_tokens_path.exists()` returned early, so an empty or
//!    expired `access-tokens.conf` satisfied it and the SOPS scrape never ran.
//!    That is exactly the "doesn't detect the PAT" case. Here, a source that
//!    parses to an EMPTY value is not a source: [`parse_access_tokens`]
//!    returns `None` for `access-tokens = github.com=`, so resolution falls
//!    through to SOPS instead of stopping on a file that carries nothing.
//! 2. **One age-key path.** The old code probed only
//!    `~/.config/sops/age/keys.txt` and warned itself into a no-op otherwise.
//!    [`age_key_candidates`] probes the four locations this fleet actually
//!    uses, `$SOPS_AGE_KEY_FILE` first, and picks the first READABLE one — a
//!    key in a non-default place then just works.
//! 3. **The token reached nix in exactly one branch.** It was forwarded only
//!    inside the darwin FIRST-RUN bootstrap; steady-state `darwin-rebuild
//!    switch` and every `nixos-rebuild` got no `--option access-tokens` at
//!    all. [`ResolvedToken::nix_option_value`] is now threaded through all
//!    three call sites.
//! 4. **Only the fleet-shared file was consulted.** A personal
//!    `users/<who>/secrets.yaml` is preferred here when present, so a build
//!    attributes its fetches to the operator running it, and the shared
//!    `github/classic` is the fleet FALLBACK rather than the only option.
//!
//! ## Readable-vs-absent is a distinction, not a detail
//!
//! `/var/lib/sops-nix/key.txt` is root-owned. `fleet rebuild` runs as the
//! operator and only sudos for the activation itself, so that key is normally
//! present-but-unreadable — a different problem from missing, with a different
//! fix. Probing with a read (rather than `exists()`) keeps the two apart, and
//! [`resolve`] simply moves on rather than treating unreadable as fatal.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where a token came from. Carried alongside the token so a later auth
/// failure can name the source that produced the credential instead of leaving
/// the operator to guess which of five places was consulted — which matters
/// most for the 404 case, where the error itself says nothing about auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// An environment variable — `GITHUB_TOKEN` or `GH_TOKEN`.
    Env(String),
    /// A nix.conf-shaped file carrying an `access-tokens` line.
    NixConf(PathBuf),
    /// Scraped from SOPS: which file, which key, decrypted with which age key.
    Sops {
        file: PathBuf,
        key: String,
        age_key: PathBuf,
    },
}

impl TokenSource {
    /// Operator-facing description. Never includes the token.
    pub fn describe(&self) -> String {
        match self {
            TokenSource::Env(var) => format!("${var}"),
            TokenSource::NixConf(path) => path.display().to_string(),
            TokenSource::Sops { file, key, age_key } => format!(
                "sops {}:{} (age key {})",
                file.display(),
                key,
                age_key.display()
            ),
        }
    }

    /// True when the token had to be decrypted — i.e. nothing on disk carried
    /// a usable credential and this is the scrape the module exists for.
    pub fn is_sops(&self) -> bool {
        matches!(self, TokenSource::Sops { .. })
    }
}

/// A non-empty GitHub token plus its provenance.
///
/// There is no constructor that accepts an empty string: every path into this
/// type goes through a check, so "resolved a token" cannot mean "resolved an
/// empty string" — the state that sends `access-tokens = github.com=` and
/// then reads as a missing REV rather than a missing credential.
#[derive(Debug, Clone)]
pub struct ResolvedToken {
    token: String,
    pub source: TokenSource,
}

impl ResolvedToken {
    fn new(token: impl Into<String>, source: TokenSource) -> Option<Self> {
        let token = token.into().trim().to_string();
        if token.is_empty() {
            return None;
        }
        Some(Self { token, source })
    }

    /// The raw secret — TEST-ONLY, and deliberately so.
    ///
    /// clippy pointed out that production never called this, which turned out
    /// to be a property worth keeping rather than a wart to silence: every
    /// production consumer goes through a renderer below
    /// ([`nix_option_value`](Self::nix_option_value),
    /// [`access_tokens_conf`](Self::access_tokens_conf), [`netrc`](Self::netrc))
    /// that puts the token in the exact shape its sink expects. With no bare
    /// accessor, there is no way to reach a `String` of the secret and pass it
    /// somewhere unintended — a `log_info("{token}")` does not compile.
    #[cfg(test)]
    pub fn expose(&self) -> &str {
        &self.token
    }

    /// The value for `--option access-tokens`.
    ///
    /// The host is `github.com`, fixed, with no knob. nix's github fetcher
    /// keys on `github.com=`, NOT `api.github.com=`; a credential filed under
    /// the api host is invisible to the fetcher, producing exactly the same
    /// 404 as having no credential at all. Making the host a constant is what
    /// keeps the wrong one unrepresentable rather than merely discouraged.
    pub fn nix_option_value(&self) -> String {
        format!("github.com={}", self.token)
    }

    /// `access-tokens.conf` file contents.
    pub fn access_tokens_conf(&self) -> String {
        format!("access-tokens = {}\n", self.nix_option_value())
    }

    /// `netrc` contents. Both hosts here on purpose: netrc feeds git and
    /// curl-shaped fetches, where `api.github.com` IS consulted.
    pub fn netrc(&self) -> String {
        format!(
            "machine api.github.com\nlogin x-access-token\npassword {t}\n\n\
             machine github.com\nlogin x-access-token\npassword {t}\n",
            t = self.token
        )
    }

    /// A safe-to-log fingerprint: the scheme prefix and the length, never the
    /// token. `ghp_****(40 chars)` is enough to tell a classic PAT from a
    /// fine-grained one and a truncated paste from a whole token.
    pub fn redacted(&self) -> String {
        let prefix: String = self.token.chars().take(4).collect();
        format!("{prefix}****({} chars)", self.token.len())
    }
}

/// The side effects token resolution needs, behind one seam so the resolution
/// ORDER can be tested without a filesystem, a sops binary, or a real secret.
pub trait TokenEnv {
    fn var(&self, key: &str) -> Option<String>;
    /// `None` for absent OR unreadable — the caller moves on either way, and
    /// [`describe_probe`] is what distinguishes them for the operator.
    fn read_file(&self, path: &Path) -> Option<String>;
    fn exists(&self, path: &Path) -> bool;
    /// Decrypt one key out of a SOPS file. `None` on any failure.
    fn sops_extract(&self, file: &Path, key: &str, age_key: &Path) -> Option<String>;
}

/// The real environment.
///
/// `sops` is resolved LAZILY and at most once. Resolving it can mean
/// `nix build nixpkgs#sops` on a node that does not carry it yet, and the
/// common case — a token already in `$GITHUB_TOKEN` or nix.conf — never needs
/// sops at all. Doing that work eagerly would put a store realisation on the
/// front of every rebuild to answer a question usually not asked.
pub struct SystemEnv {
    resolve_sops: Box<dyn Fn() -> String>,
    cached_sops: std::cell::OnceCell<String>,
}

impl SystemEnv {
    /// `resolve_sops` is invoked at most once, and only if a SOPS scrape is
    /// actually reached.
    pub fn new(resolve_sops: impl Fn() -> String + 'static) -> Self {
        Self {
            resolve_sops: Box::new(resolve_sops),
            cached_sops: std::cell::OnceCell::new(),
        }
    }

    fn sops_cmd(&self) -> &str {
        self.cached_sops.get_or_init(|| (self.resolve_sops)())
    }
}

impl TokenEnv for SystemEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok().filter(|v| !v.trim().is_empty())
    }

    fn read_file(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn sops_extract(&self, file: &Path, key: &str, age_key: &Path) -> Option<String> {
        let out = Command::new(self.sops_cmd())
            .arg("--decrypt")
            .arg("--extract")
            .arg(key)
            .arg(file)
            .env("SOPS_AGE_KEY_FILE", age_key)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout).ok()
    }
}

/// Pull the `github.com` token out of nix.conf-shaped text.
///
/// Handles both spellings nix accepts (`access-tokens = …` and
/// `extra-access-tokens = …`), multiple space-separated host=token pairs, and
/// files with unrelated lines around the one that matters.
///
/// **Returns `None` for a present-but-empty value.** `access-tokens =
/// github.com=` is a real shape on a node whose secret rendered before the
/// secret existed, and treating it as a hit is the whole defect this module
/// replaces.
pub fn parse_access_tokens(content: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.trim();
        // `continue`, NOT `?`. An early version used `?` here, which returns
        // from the whole function on the first line that is not an
        // access-tokens line — so a real /etc/nix/nix.conf, where the token
        // sits below `experimental-features = …`, parsed as "no token" and
        // sent every rebuild down the SOPS scrape. Every test had the token on
        // line 1, so all of them passed.
        let Some(rest) = line
            .strip_prefix("access-tokens")
            .or_else(|| line.strip_prefix("extra-access-tokens"))
        else {
            continue;
        };
        let Some(rest) = rest.trim_start().strip_prefix('=') else {
            continue;
        };
        for pair in rest.split_whitespace() {
            if let Some(tok) = pair.strip_prefix("github.com=") {
                if !tok.trim().is_empty() {
                    return Some(tok.trim().to_string());
                }
            }
        }
    }
    None
}

/// Age-key locations this fleet actually uses, in precedence order, deduped.
///
/// Deduping matters for the operator-facing probe as much as for correctness:
/// `$SOPS_AGE_KEY_FILE` is very often set to the default path, and listing the
/// same file twice makes the report read like it found two keys.
pub fn age_key_candidates(home: &Path, env_key: Option<&str>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(k) = env_key.map(str::trim).filter(|k| !k.is_empty()) {
        push(PathBuf::from(k));
    }
    push(home.join(".config/sops/age/keys.txt"));
    // The node key sops-nix installs. Root-owned, so normally unreadable to
    // the operator — present here because a rebuild run under sudo CAN use it.
    push(PathBuf::from("/var/lib/sops-nix/key.txt"));
    push(home.join(".age/keys.txt"));
    push(home.join(".config/sops/age/key.txt"));
    out
}

/// nix.conf-shaped files that may already carry a credential, in the order
/// nix itself would find them.
///
/// `/root/.config/nix/` is in the list because on NixOS the nix DAEMON runs as
/// root and reads root's config; `access-tokens` is a trusted-user-only
/// setting, so a non-trusted user's value is silently dropped and the root
/// file is the one that was actually in play.
pub fn nix_conf_candidates(home: &Path) -> Vec<PathBuf> {
    vec![
        home.join(".config/nix/access-tokens.conf"),
        home.join(".config/nix/nix.conf"),
        PathBuf::from("/etc/nix/access-tokens.conf"),
        PathBuf::from("/etc/nix/nix.conf"),
        PathBuf::from("/root/.config/nix/access-tokens.conf"),
    ]
}

/// SOPS files to scrape, in preference order: the operator's own file first,
/// the fleet-shared one as fallback.
///
/// Personal first is an ATTRIBUTION choice, not a security one. Both tokens
/// work. `github/classic` in the shared file is one person's token doing fleet
/// duty, so building with it attributes every fetch to them; when the operator
/// has their own, theirs should be the one on the wire. When they do not — a
/// fresh node, an unonboarded operator — the shared token is what keeps the
/// bootstrap unblocked, which is why it stays in the chain rather than being
/// refused.
pub fn sops_candidates(flake_root: &Path, user: Option<&str>) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    if let Some(user) = user.map(str::trim).filter(|u| !u.is_empty()) {
        out.push((
            flake_root.join("users").join(user).join("secrets.yaml"),
            r#"["github"]["pat"]"#.to_string(),
        ));
    }
    out.push((
        flake_root.join("secrets.yaml"),
        r#"["github"]["classic"]"#.to_string(),
    ));
    out
}

/// A read-only account of what was probed and what was found. Printed when
/// resolution FAILS, so the operator gets a diagnosis instead of a question.
pub struct ProbeReport {
    pub lines: Vec<String>,
}

/// Resolve a GitHub token from the first source that actually yields one.
///
/// Order: `$GITHUB_TOKEN` → `$GH_TOKEN` → nix.conf-shaped files → SOPS
/// (personal, then fleet-shared). Env and nix.conf come first because a token
/// already in play should not be silently replaced by a different one; SOPS is
/// the fallback for when none of them carry anything usable.
pub fn resolve<E: TokenEnv>(
    env: &E,
    home: &Path,
    flake_root: &Path,
    user: Option<&str>,
) -> (Option<ResolvedToken>, ProbeReport) {
    let mut lines = Vec::new();

    for var in ["GITHUB_TOKEN", "GH_TOKEN"] {
        if let Some(v) = env.var(var) {
            if let Some(t) = ResolvedToken::new(v, TokenSource::Env(var.to_string())) {
                lines.push(format!("  FOUND     ${var}"));
                return (Some(t), ProbeReport { lines });
            }
            lines.push(format!("  empty     ${var}"));
        }
    }

    for path in nix_conf_candidates(home) {
        match env.read_file(&path) {
            Some(content) => match parse_access_tokens(&content) {
                Some(tok) => {
                    if let Some(t) = ResolvedToken::new(tok, TokenSource::NixConf(path.clone())) {
                        lines.push(format!("  FOUND     {}", path.display()));
                        return (Some(t), ProbeReport { lines });
                    }
                    lines.push(format!("  EMPTY token in {}", path.display()));
                }
                None => lines.push(format!("  no github.com= entry in {}", path.display())),
            },
            None if env.exists(&path) => {
                lines.push(format!("  exists but NOT READABLE  {}", path.display()));
            }
            None => lines.push(format!("  absent    {}", path.display())),
        }
    }

    // Nothing on disk. Scrape SOPS — which needs a readable age key first.
    let env_key = env.var("SOPS_AGE_KEY_FILE");
    let age_keys = age_key_candidates(home, env_key.as_deref());
    let mut usable_key: Option<PathBuf> = None;
    for k in &age_keys {
        if env.read_file(k).is_some() {
            lines.push(format!("  READABLE  age key {}", k.display()));
            usable_key = Some(k.clone());
            break;
        } else if env.exists(k) {
            lines.push(format!("  exists but NOT READABLE  age key {}", k.display()));
        } else {
            lines.push(format!("  absent    age key {}", k.display()));
        }
    }

    let Some(age_key) = usable_key else {
        return (None, ProbeReport { lines });
    };

    for (file, key) in sops_candidates(flake_root, user) {
        if !env.exists(&file) {
            lines.push(format!("  absent    {}", file.display()));
            continue;
        }
        match env.sops_extract(&file, &key, &age_key) {
            Some(raw) => {
                let source = TokenSource::Sops {
                    file: file.clone(),
                    key: key.clone(),
                    age_key: age_key.clone(),
                };
                if let Some(t) = ResolvedToken::new(raw, source) {
                    lines.push(format!("  FOUND     {} {}", file.display(), key));
                    return (Some(t), ProbeReport { lines });
                }
                // sops exits 0 having printed nothing for an empty value, so
                // this branch is reachable and is NOT an error to sops.
                lines.push(format!("  EMPTY     {} {}", file.display(), key));
            }
            None => lines.push(format!(
                "  could not decrypt {} {} (are you a recipient?)",
                file.display(),
                key
            )),
        }
    }

    (None, ProbeReport { lines })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct MockEnv {
        vars: HashMap<String, String>,
        files: HashMap<PathBuf, String>,
        /// Present but unreadable — `exists` true, `read_file` None.
        opaque: Vec<PathBuf>,
        sops: HashMap<(PathBuf, String), String>,
    }

    impl TokenEnv for MockEnv {
        fn var(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned().filter(|v| !v.trim().is_empty())
        }
        fn read_file(&self, path: &Path) -> Option<String> {
            self.files.get(path).cloned()
        }
        fn exists(&self, path: &Path) -> bool {
            self.files.contains_key(path)
                || self.opaque.contains(&path.to_path_buf())
                // A SOPS file is on disk even though its PLAINTEXT is not
                // readable — that is the whole point of it being encrypted.
                // Modelling it any other way makes `resolve`'s existence gate
                // skip every sops candidate.
                || self.sops.keys().any(|(f, _)| f == path)
        }
        fn sops_extract(&self, file: &Path, key: &str, _age: &Path) -> Option<String> {
            self.sops.get(&(file.to_path_buf(), key.to_string())).cloned()
        }
    }

    fn home() -> PathBuf {
        PathBuf::from("/home/op")
    }
    fn root() -> PathBuf {
        PathBuf::from("/flake")
    }

    #[test]
    fn parses_a_plain_access_tokens_line() {
        assert_eq!(
            parse_access_tokens("access-tokens = github.com=ghp_abc\n").as_deref(),
            Some("ghp_abc")
        );
    }

    #[test]
    fn parses_the_extra_spelling_and_multiple_hosts() {
        let c = "extra-access-tokens = gitlab.com=x github.com=ghp_zzz\n";
        assert_eq!(parse_access_tokens(c).as_deref(), Some("ghp_zzz"));
    }

    /// A real `/etc/nix/nix.conf` does not lead with the token. Regression
    /// test for a `?`-instead-of-`continue` in this parser that made every
    /// such file read as "no token".
    #[test]
    fn finds_the_token_below_other_settings() {
        let c = "experimental-features = nix-command flakes\n\
                 substituters = https://cache.nixos.org\n\
                 access-tokens = github.com=ghp_deep\n\
                 warn-dirty = false\n";
        assert_eq!(parse_access_tokens(c).as_deref(), Some("ghp_deep"));
    }

    #[test]
    fn tolerates_an_include_line_and_comments() {
        let c = "# managed by nix-darwin\n\
                 !include /etc/nix/access-tokens.conf\n\
                 access-tokens = github.com=ghp_after_include\n";
        assert_eq!(parse_access_tokens(c).as_deref(), Some("ghp_after_include"));
    }

    /// THE defect this module replaces: an empty value is not a token. The old
    /// gate accepted this file's mere existence and never scraped SOPS.
    #[test]
    fn an_empty_value_is_not_a_token() {
        assert_eq!(parse_access_tokens("access-tokens = github.com=\n"), None);
        assert_eq!(parse_access_tokens(""), None);
        assert_eq!(parse_access_tokens("access-tokens = gitlab.com=y\n"), None);
    }

    /// …and end-to-end: an empty conf must fall THROUGH to the SOPS scrape
    /// rather than stopping resolution.
    #[test]
    fn empty_nix_conf_falls_through_to_sops() {
        let mut env = MockEnv::default();
        env.files.insert(
            home().join(".config/nix/access-tokens.conf"),
            "access-tokens = github.com=\n".into(),
        );
        env.files
            .insert(home().join(".config/sops/age/keys.txt"), "AGE-KEY".into());
        env.sops.insert(
            (root().join("secrets.yaml"), r#"["github"]["classic"]"#.into()),
            "ghp_from_sops".into(),
        );

        let (tok, _) = resolve(&env, &home(), &root(), None);
        let tok = tok.expect("must fall through to sops");
        assert_eq!(tok.expose(), "ghp_from_sops");
        assert!(tok.source.is_sops());
    }

    #[test]
    fn env_wins_over_everything() {
        let mut env = MockEnv::default();
        env.vars.insert("GITHUB_TOKEN".into(), "ghp_env".into());
        env.files.insert(
            home().join(".config/nix/access-tokens.conf"),
            "access-tokens = github.com=ghp_file\n".into(),
        );
        let (tok, _) = resolve(&env, &home(), &root(), None);
        assert_eq!(tok.unwrap().expose(), "ghp_env");
    }

    #[test]
    fn a_usable_nix_conf_short_circuits_the_scrape() {
        let mut env = MockEnv::default();
        env.files.insert(
            home().join(".config/nix/access-tokens.conf"),
            "access-tokens = github.com=ghp_file\n".into(),
        );
        let (tok, _) = resolve(&env, &home(), &root(), None);
        let tok = tok.unwrap();
        assert_eq!(tok.expose(), "ghp_file");
        assert!(!tok.source.is_sops(), "must not scrape when disk has one");
    }

    #[test]
    fn personal_pat_is_preferred_over_the_shared_classic() {
        let mut env = MockEnv::default();
        env.files
            .insert(home().join(".config/sops/age/keys.txt"), "AGE".into());
        env.sops.insert(
            (
                root().join("users/op/secrets.yaml"),
                r#"["github"]["pat"]"#.into(),
            ),
            "ghp_personal".into(),
        );
        env.sops.insert(
            (root().join("secrets.yaml"), r#"["github"]["classic"]"#.into()),
            "ghp_shared".into(),
        );
        let (tok, _) = resolve(&env, &home(), &root(), Some("op"));
        assert_eq!(tok.unwrap().expose(), "ghp_personal");
    }

    #[test]
    fn falls_back_to_shared_classic_when_there_is_no_personal_file() {
        let mut env = MockEnv::default();
        env.files
            .insert(home().join(".config/sops/age/keys.txt"), "AGE".into());
        env.sops.insert(
            (root().join("secrets.yaml"), r#"["github"]["classic"]"#.into()),
            "ghp_shared".into(),
        );
        let (tok, _) = resolve(&env, &home(), &root(), Some("op"));
        assert_eq!(tok.unwrap().expose(), "ghp_shared");
    }

    /// Present-but-unreadable must be REPORTED as such, not as absent: they
    /// are different problems with different fixes.
    #[test]
    fn an_unreadable_age_key_is_reported_distinctly_from_a_missing_one() {
        let mut env = MockEnv::default();
        env.opaque.push(PathBuf::from("/var/lib/sops-nix/key.txt"));
        let (tok, report) = resolve(&env, &home(), &root(), None);
        assert!(tok.is_none());
        let joined = report.lines.join("\n");
        assert!(
            joined.contains("NOT READABLE  age key /var/lib/sops-nix/key.txt"),
            "report was:\n{joined}"
        );
        assert!(joined.contains("absent    age key /home/op/.config/sops/age/keys.txt"));
    }

    #[test]
    fn no_age_key_means_no_token_and_no_panic() {
        let env = MockEnv::default();
        let (tok, _) = resolve(&env, &home(), &root(), Some("op"));
        assert!(tok.is_none());
    }

    /// sops exits 0 printing nothing when the key holds an empty value; that
    /// must not resolve to a token that produces a 404 on the next private
    /// input, twenty minutes into a build.
    #[test]
    fn an_empty_sops_value_does_not_resolve() {
        let mut env = MockEnv::default();
        env.files
            .insert(home().join(".config/sops/age/keys.txt"), "AGE".into());
        env.sops.insert(
            (root().join("secrets.yaml"), r#"["github"]["classic"]"#.into()),
            "   \n".into(),
        );
        let (tok, _) = resolve(&env, &home(), &root(), None);
        assert!(tok.is_none());
    }

    #[test]
    fn env_key_is_probed_first_and_deduped() {
        let c = age_key_candidates(&home(), Some("/custom/key.txt"));
        assert_eq!(c[0], PathBuf::from("/custom/key.txt"));
        let dup = age_key_candidates(&home(), Some("/home/op/.config/sops/age/keys.txt"));
        assert_eq!(
            dup.iter()
                .filter(|p| p.ends_with(".config/sops/age/keys.txt"))
                .count(),
            1
        );
    }

    #[test]
    fn the_nix_option_always_uses_the_fetcher_host() {
        let t = ResolvedToken::new("ghp_x", TokenSource::Env("GITHUB_TOKEN".into())).unwrap();
        assert_eq!(t.nix_option_value(), "github.com=ghp_x");
        assert_eq!(t.access_tokens_conf(), "access-tokens = github.com=ghp_x\n");
    }

    #[test]
    fn the_redaction_never_leaks_the_token() {
        let t = ResolvedToken::new("ghp_supersecretvalue", TokenSource::Env("X".into())).unwrap();
        let r = t.redacted();
        assert!(!r.contains("supersecret"), "leaked: {r}");
        assert!(r.starts_with("ghp_"));
    }

    #[test]
    fn an_empty_token_cannot_be_constructed() {
        assert!(ResolvedToken::new("  ", TokenSource::Env("X".into())).is_none());
    }
}
