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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process;
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
            lines.push(format!(
                "  exists but NOT READABLE  age key {}",
                k.display()
            ));
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

// ─────────────────────────────────────────────────────────────────────
// INJECTION — the write half.
//
// ★ WHY THIS EXISTS. Everything above RESOLVES a token and renders it into
// the shape a sink wants; until this block, nothing PERSISTED it. The only
// consumer was `--option access-tokens` appended to a rebuild's argv, which
// dies with the process. So every other place that needed a credential on
// disk grew its own writer: the nix repo alone carries 8 retrieval sites and
// 13 injection sites, and a hand-typed shell one-liner became the 14th on plo
// on 2026-08-16. One brain, fourteen hands.
//
// The retrieval brain was never the problem. Its position was: it lives
// inside `fleet`, and the operator reaches `fleet` through `nix run .#rebuild`
// — which must first EVALUATE a flake with ~160 private inputs, which is the
// very thing the credential unblocks. The brain stood behind the door it
// exists to open. Giving it a write half plus a standalone verb is what lets
// it be called BEFORE nix loads (the repo's `.envrc`), from a PUBLIC flake
// reference that needs no credential to fetch.
//
// ★ TWO TRAPS ENCODED HERE, both measured rather than imagined.
//
// 1. A DANGLING SYMLINK IS NOT AN ABSENT FILE. `Path::exists()` FOLLOWS
//    symlinks, so a link whose target evaporated reads as "absent" — and then
//    the write through it fails ENOENT rather than creating anything. That is
//    exactly the darwin steady state: `~/.config/nix/access-tokens.conf` is a
//    symlink into a 64 MB HFS ramdisk that macOS destroys on every boot. A
//    seeder that tests `exists()` and then writes is a guaranteed no-op in the
//    one state it was written for. [`clear_dangling`] separates the cases with
//    `symlink_metadata` and removes the corpse before writing.
//
// 2. AN UNREADABLE `!include` TARGET IS SILENTLY SKIPPED. nix reads an include
//    as whichever user runs the command and ignores one it cannot open — no
//    error, no warning, exit 0. Red-run 2026-08-16: a `0400 root:wheel` target
//    yields EMPTY `access-tokens` and rc=0 for the operator. So the token file
//    is written 0600 owned by the CALLER, never root-owned on the caller's
//    behalf, and the write is verified by reading it back.
// ─────────────────────────────────────────────────────────────────────

/// Is `bin` on `PATH`? A dependency-free `command -v`.
fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// `sops`, building it from nixpkgs if the node does not carry it yet — a
/// pre-activation node generally does not, and that is exactly when a
/// credential needs seeding.
fn default_sops_cmd() -> String {
    if on_path("sops") {
        return "sops".to_string();
    }
    let out = Command::new("nix")
        .args([
            "--extra-experimental-features",
            "nix-command flakes",
            "build",
            "--print-out-paths",
            "--no-link",
            "nixpkgs#sops",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let p = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if p.is_empty() {
                "sops".to_string()
            } else {
                format!("{p}/bin/sops")
            }
        }
        // Non-fatal: resolution then finds no SOPS source and falls back to
        // whatever the env / nix.conf already carry.
        _ => "sops".to_string(),
    }
}

/// The canonical [`SystemEnv`] for production callers.
///
/// `commands::rebuild` still carries a private twin of this (it logs through
/// the fleet loggers, which this module deliberately does not depend on). That
/// twin should collapse onto this one; it is left alone here only because its
/// file carries unrelated uncommitted work.
pub fn system_env() -> SystemEnv {
    SystemEnv::new(default_sops_cmd)
}

/// The pair of files one injection touches: the credential itself, and the
/// nix.conf that points at it.
///
/// Kept as a pair rather than a single path because writing the credential
/// without the `!include` is a silent no-op — nix never looks at a file
/// nothing references — and that half-done state is indistinguishable from
/// success unless the two always move together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialTarget {
    pub token_file: PathBuf,
    pub nix_conf: PathBuf,
}

impl CredentialTarget {
    /// The caller's own config. This is the target that matters for flake
    /// EVALUATION, which runs as the operator.
    pub fn user(home: &Path) -> Self {
        Self {
            token_file: home.join(".config/nix/access-tokens.conf"),
            nix_conf: home.join(".config/nix/nix.conf"),
        }
    }

    /// Root's config. Separate because `sudo` drops the caller's `HOME`, so
    /// the sudo'd half of a rebuild reads this one and nothing else.
    pub fn root() -> Self {
        Self {
            token_file: PathBuf::from("/root/.config/nix/access-tokens.conf"),
            nix_conf: PathBuf::from("/root/.config/nix/nix.conf"),
        }
    }

    /// The line nix.conf must carry. Relative when the two files are
    /// co-located — nix resolves an include against the including file's own
    /// directory, so the short form is correct and survives the pair being
    /// moved together.
    pub fn include_line(&self) -> String {
        let same_dir = self.token_file.parent() == self.nix_conf.parent();
        if same_dir {
            match self.token_file.file_name().and_then(|n| n.to_str()) {
                Some(name) => format!("!include {name}"),
                None => format!("!include {}", self.token_file.display()),
            }
        } else {
            format!("!include {}", self.token_file.display())
        }
    }
}

/// What an [`ensure`] call actually did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Injection {
    /// The credential was already present and current. NOTHING was written.
    /// This is the common case and the one that makes calling `ensure` from a
    /// shell hook cheap: one stat plus one read.
    AlreadyCurrent,
    /// The credential was written (or rewritten).
    Wrote,
}

/// The concrete edit an injection would make. Produced by the PURE
/// [`plan_injection`] so the decision is testable without a filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectionPlan {
    /// Full new contents for the credential file.
    pub token_file: String,
    /// Full new contents for nix.conf, or `None` when it already includes.
    pub nix_conf: Option<String>,
}

/// Split an `access-tokens` VALUE into `host=token` entries.
fn access_tokens_entries(value: &str) -> Vec<(String, String)> {
    value
        .split_whitespace()
        .filter_map(|e| e.split_once('='))
        .map(|(h, t)| (h.to_string(), t.to_string()))
        .collect()
}

/// The `access-tokens` value currently declared in nix.conf-shaped `text`.
fn access_tokens_value(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix("access-tokens"))
        .and_then(|rest| rest.trim_start().strip_prefix('='))
        .map(|v| v.trim().to_string())
}

/// Upsert `github.com` into an existing `access-tokens` line, PRESERVING every
/// other host.
///
/// A node can legitimately carry a second forge (a GitHub Enterprise host, a
/// gitlab mirror). Rewriting the whole line from one token would silently
/// delete those, and the failure would surface much later as an unrelated
/// fetch failing — so co-resident hosts are carried through untouched.
fn upsert_github_entry(existing: Option<&str>, token: &ResolvedToken) -> String {
    // `existing` is the whole FILE, so the value has to be extracted before it
    // is split into entries. Splitting the raw file instead parses the bare
    // `=` of `access-tokens = …` as an entry with an empty host, and the
    // rendered line comes back as `access-tokens = = github.com=…` — which nix
    // then rejects wholesale, taking the real credential down with it. Caught
    // by `a_rotated_token_rewrites_the_credential_but_not_the_include`.
    let value = existing.and_then(access_tokens_value);
    let mut entries: Vec<(String, String)> = value
        .as_deref()
        .map(access_tokens_entries)
        .unwrap_or_default();
    let value = token.nix_option_value();
    let (host, tok) = value
        .split_once('=')
        .expect("nix_option_value is host=token");
    match entries.iter_mut().find(|(h, _)| h == host) {
        Some(slot) => slot.1 = tok.to_string(),
        None => entries.push((host.to_string(), tok.to_string())),
    }
    let rendered: Vec<String> = entries.iter().map(|(h, t)| format!("{h}={t}")).collect();
    format!("access-tokens = {}\n", rendered.join(" "))
}

/// PURE: decide what the two files should become. `None` means already
/// current — the fast path a shell hook takes on every invocation but the
/// first.
pub fn plan_injection(
    current_token_file: Option<&str>,
    current_nix_conf: Option<&str>,
    token: &ResolvedToken,
    target: &CredentialTarget,
) -> Option<InjectionPlan> {
    let desired_token_file = upsert_github_entry(current_token_file, token);
    let token_file_current = current_token_file.is_some_and(|c| c == desired_token_file);

    let want = target.include_line();
    let nix_conf_current = current_nix_conf.is_some_and(|c| c.lines().any(|l| l.trim() == want));

    if token_file_current && nix_conf_current {
        return None;
    }

    let nix_conf = if nix_conf_current {
        None
    } else {
        let mut body = current_nix_conf.unwrap_or_default().to_string();
        if !body.is_empty() && !body.ends_with('\n') {
            body.push('\n');
        }
        body.push_str(&want);
        body.push('\n');
        Some(body)
    };

    Some(InjectionPlan {
        token_file: desired_token_file,
        nix_conf,
    })
}

/// Remove `path` if — and only if — it is a symlink whose target does not
/// resolve. See trap 1 in this section's header.
fn clear_dangling(path: &Path) -> std::io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() && std::fs::metadata(path).is_err() => {
            std::fs::remove_file(path)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Write `contents` to `path` with mode 0600, creating parents.
fn write_private(path: &Path, contents: &str) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// What [`ensure`] did, in operator-facing terms. Never carries the token.
pub struct EnsureReport {
    pub injection: Injection,
    pub target: CredentialTarget,
    pub source: TokenSource,
    pub redacted: String,
    /// Dangling symlinks removed to make the write possible. Reported because
    /// their presence means the sops render evaporated, which the operator
    /// may want to fix at the source rather than keep papering over.
    pub cleared: Vec<PathBuf>,
}

/// Resolve a token and make it present on disk for `target`, idempotently.
///
/// This is the one function the whole module exists to offer: retrieve from
/// wherever a credential can be found, then inject it where nix will actually
/// read it — with no secret in argv or the environment at any point.
pub fn ensure<E: TokenEnv>(
    env: &E,
    home: &Path,
    flake_root: &Path,
    user: Option<&str>,
    target: &CredentialTarget,
) -> Result<EnsureReport, String> {
    let (token, probe) = resolve(env, home, flake_root, user);
    let token = token.ok_or_else(|| {
        let mut msg = String::from("no GitHub token could be resolved:\n");
        for l in &probe.lines {
            msg.push_str(l);
            msg.push('\n');
        }
        msg
    })?;

    let mut cleared = Vec::new();
    for p in [&target.token_file, &target.nix_conf] {
        match clear_dangling(p) {
            Ok(true) => cleared.push(p.clone()),
            Ok(false) => {}
            Err(e) => return Err(format!("could not clear dangling {}: {e}", p.display())),
        }
    }

    let current_token_file = std::fs::read_to_string(&target.token_file).ok();
    let current_nix_conf = std::fs::read_to_string(&target.nix_conf).ok();

    let plan = plan_injection(
        current_token_file.as_deref(),
        current_nix_conf.as_deref(),
        &token,
        target,
    );

    let injection = match plan {
        None => Injection::AlreadyCurrent,
        Some(plan) => {
            write_private(&target.token_file, &plan.token_file)
                .map_err(|e| format!("could not write {}: {e}", target.token_file.display()))?;
            if let Some(conf) = plan.nix_conf {
                if let Some(dir) = target.nix_conf.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|e| format!("could not create {}: {e}", dir.display()))?;
                }
                std::fs::write(&target.nix_conf, conf)
                    .map_err(|e| format!("could not write {}: {e}", target.nix_conf.display()))?;
            }
            // Verify by reading back. A write that reports success and leaves
            // nothing readable is precisely the failure mode this module was
            // built to end, so it is checked rather than assumed.
            let back = std::fs::read_to_string(&target.token_file).map_err(|e| {
                format!(
                    "wrote {} but cannot read it back: {e}",
                    target.token_file.display()
                )
            })?;
            if access_tokens_value(&back)
                .map(|v| !v.contains("github.com="))
                .unwrap_or(true)
            {
                return Err(format!(
                    "wrote {} but it carries no github.com entry",
                    target.token_file.display()
                ));
            }
            Injection::Wrote
        }
    };

    Ok(EnsureReport {
        injection,
        target: target.clone(),
        source: token.source.clone(),
        redacted: token.redacted(),
        cleared,
    })
}

// ─────────────────────────────────────────────────────────────────────
// TRANSPORT — handing the credential to a child `nix` WITHOUT argv.
//
// ★ WHY THIS EXISTS. Every resolution path above ended at one sink:
// `--option access-tokens github.com=<tok>` appended to a rebuild's argv.
// argv is world-readable — `ps` on macOS and `/proc/<pid>/cmdline` on Linux
// hand the fleet PAT to any local process for the whole multi-minute life of
// a `darwin-rebuild switch`. Measured 2026-08-29 on cid: the token was
// legible in `ps aux` output during a routine rebuild. That is the
// zero-plaintext discipline (never argv, env or logs) violated by the one
// command every operator runs the most.
//
// The fix is a TRANSPORT swap, not a policy change. nix parses `NIX_CONFIG`
// with the same parser as nix.conf, `!include` directives and all, so a 0600
// file plus `NIX_CONFIG=!include <path>` reaches exactly the same setting
// with exactly the same override precedence as `--option` did. Verified
// 2026-08-29 against the live binary: `NIX_CONFIG="!include f" nix config
// show` prints the file's `access-tokens` and REPLACES the ambient value —
// identical semantics, so this is a byte-for-byte behavioural no-op at the
// setting level while the secret stops travelling in argv. What crosses the
// process boundary is a PATH; the env carries no credential either.
//
// ★ TWO TRAPS, both inherited from the injection block above and re-encoded
// here because this file is created fresh rather than found.
//
// 1. AN UNREADABLE `!include` TARGET IS SILENTLY SKIPPED — no error, no
//    warning, exit 0, empty `access-tokens`. A rebuild elevates through
//    `sudo`, so the reader is root while the writer is the operator: root
//    reads a 0600 user file fine, but the DIRECTORY must be traversable too,
//    which is why the mode is set at creation rather than left to umask.
//    A silent skip here is indistinguishable from having no token, which is
//    the 404-that-says-nothing-about-auth failure this module was built for.
//    RED-RUN 2026-08-29 against the live nix, so this is measured rather than
//    argued: `NIX_CONFIG="!include /path/that/does/not/exist" nix config show`
//    exits 0, prints no diagnostic, and quietly falls back to the ambient
//    `access-tokens`. On a workstation that fallback happens to be the right
//    credential; on the bootstrap node this module exists for, it is nothing.
//    Hence [`TokenConfigFile`] is bound for the whole rebuild rather than
//    built as a temporary — a value dropped at the end of its own statement
//    would leave the child pointing at a deleted file and failing THIS way.
//
// 2. THE FILE MUST NOT OUTLIVE THE REBUILD. It is a plaintext credential on
//    disk; `Drop` removes the whole directory so a panic or an early return
//    cannot leave one behind. It is deliberately NOT written into
//    `~/.config/nix` — that is sops-nix's territory after activation, and the
//    injection block above already refuses to clobber it.
// ─────────────────────────────────────────────────────────────────────

/// A short-lived 0600 file carrying `access-tokens = …`, plus the
/// `NIX_CONFIG` value that points a child `nix` at it.
///
/// Holds no accessor returning the token: the only way out is
/// [`Self::nix_config_value`], which yields a path. Passing the secret
/// somewhere unintended does not compile, the same guarantee
/// [`ResolvedToken`] makes.
pub struct TokenConfigFile {
    dir: PathBuf,
    path: PathBuf,
}

impl TokenConfigFile {
    /// Materialize the token as a private nix.conf fragment.
    ///
    /// ★ The directory name must be unique per INSTANCE, not per process.
    /// Keying it on `process::id()` alone was wrong and the tests below caught
    /// it: two `TokenConfigFile`s alive in one process land on the same path,
    /// and the first one's `Drop` deletes the second one's file — after which
    /// `!include` points at nothing and nix skips it SILENTLY (trap 1). A pid
    /// is also reusable after a crash, so the collision is reachable across
    /// runs too, not only within one. The counter makes each instance its own
    /// directory; `create_new` then refuses rather than adopting a path that
    /// somehow already exists, so a stale corpse is never written into.
    pub fn create(token: &ResolvedToken) -> std::io::Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);

        let dir = std::env::temp_dir().join(format!("fleet-access-tokens-{}-{seq}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::DirBuilder::new()
            .mode(0o700)
            .recursive(true)
            .create(&dir)?;

        let path = dir.join("access-tokens.conf");
        fs::write(&path, token.access_tokens_conf())?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        Ok(Self { dir, path })
    }

    /// The `NIX_CONFIG` value a child process needs. Carries a path, never a
    /// credential — safe to log, and safe in an environment block.
    pub fn nix_config_value(&self) -> String {
        format!("!include {}", self.path.display())
    }

    /// Compose onto whatever `NIX_CONFIG` the caller's environment already
    /// holds, so this adds a setting rather than silently discarding an
    /// operator's own config. nix's parser takes one directive per line.
    pub fn compose_nix_config(&self, existing: Option<&str>) -> String {
        match existing.map(str::trim).filter(|s| !s.is_empty()) {
            Some(prev) => format!("{prev}\n{}", self.nix_config_value()),
            None => self.nix_config_value(),
        }
    }
}

impl Drop for TokenConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── TRANSPORT ────────────────────────────────────────────────────
    // The credential must reach nix WITHOUT ever entering argv.

    fn probe_token() -> ResolvedToken {
        ResolvedToken::new("ghp_probe_token_value", TokenSource::Env("PROBE".into()))
            .expect("non-empty")
    }

    #[test]
    fn token_config_file_holds_the_access_tokens_line() {
        let conf = TokenConfigFile::create(&probe_token()).expect("write");
        let body = fs::read_to_string(&conf.path).expect("read back");
        assert_eq!(body, "access-tokens = github.com=ghp_probe_token_value\n");
    }

    #[test]
    fn token_config_file_is_owner_only() {
        let conf = TokenConfigFile::create(&probe_token()).expect("write");
        // A credential readable by other local users defeats the whole point
        // of moving it off argv.
        let mode = fs::metadata(&conf.path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be 0600, got {mode:o}");
        let dmode = fs::metadata(&conf.dir).expect("stat").permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "token dir must be 0700, got {dmode:o}");
    }

    #[test]
    fn nix_config_value_carries_a_path_never_the_token() {
        let token = probe_token();
        let conf = TokenConfigFile::create(&token).expect("write");
        let value = conf.nix_config_value();
        assert!(value.starts_with("!include "), "got {value}");
        // The whole invariant in one assertion: what crosses the process
        // boundary must not contain the secret.
        assert!(
            !value.contains(token.expose()),
            "NIX_CONFIG value leaked the token"
        );
    }

    #[test]
    fn compose_nix_config_preserves_an_operator_value() {
        let conf = TokenConfigFile::create(&probe_token()).expect("write");
        let composed = conf.compose_nix_config(Some("warn-dirty = false"));
        assert_eq!(
            composed,
            format!("warn-dirty = false\n{}", conf.nix_config_value()),
            "an operator's own NIX_CONFIG must survive, one directive per line"
        );
        // Empty and absent both mean "nothing to preserve" — neither may emit
        // a leading blank line, which nix parses as a directive.
        assert_eq!(conf.compose_nix_config(None), conf.nix_config_value());
        assert_eq!(
            conf.compose_nix_config(Some("   ")),
            conf.nix_config_value()
        );
    }

    #[test]
    fn dropping_the_config_file_removes_the_credential_from_disk() {
        let path = {
            let conf = TokenConfigFile::create(&probe_token()).expect("write");
            conf.path.clone()
        };
        assert!(
            !path.exists(),
            "a plaintext credential survived the rebuild that needed it"
        );
    }

    #[test]
    fn two_live_config_files_do_not_share_a_path() {
        // Regression: keyed on pid alone, these collided — and the FIRST
        // one's Drop deleted the SECOND one's file, leaving `!include`
        // pointing at nothing, which nix skips without a word.
        let a = TokenConfigFile::create(&probe_token()).expect("write a");
        let b = TokenConfigFile::create(&probe_token()).expect("write b");
        assert_ne!(a.path, b.path, "two instances shared one path");
        assert!(
            a.path.exists() && b.path.exists(),
            "one clobbered the other"
        );

        drop(a);
        assert!(
            b.path.exists(),
            "dropping one config file destroyed another's credential"
        );
    }

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
            self.sops
                .get(&(file.to_path_buf(), key.to_string()))
                .cloned()
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
            (
                root().join("secrets.yaml"),
                r#"["github"]["classic"]"#.into(),
            ),
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
            (
                root().join("secrets.yaml"),
                r#"["github"]["classic"]"#.into(),
            ),
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
            (
                root().join("secrets.yaml"),
                r#"["github"]["classic"]"#.into(),
            ),
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
            (
                root().join("secrets.yaml"),
                r#"["github"]["classic"]"#.into(),
            ),
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

    // ── injection: the PURE core, tested without a filesystem ────────

    fn tok(v: &str) -> ResolvedToken {
        ResolvedToken::new(v, TokenSource::Env("TEST".into())).unwrap()
    }

    fn user_target() -> CredentialTarget {
        CredentialTarget::user(Path::new("/home/u"))
    }

    #[test]
    fn a_co_located_pair_gets_the_relative_include_form() {
        assert_eq!(user_target().include_line(), "!include access-tokens.conf");
    }

    #[test]
    fn a_split_pair_gets_an_absolute_include() {
        let t = CredentialTarget {
            token_file: PathBuf::from("/var/lib/pleme/access-tokens.conf"),
            nix_conf: PathBuf::from("/home/u/.config/nix/nix.conf"),
        };
        assert_eq!(
            t.include_line(),
            "!include /var/lib/pleme/access-tokens.conf"
        );
    }

    #[test]
    fn a_fresh_machine_gets_both_files_written() {
        let plan = plan_injection(None, None, &tok("ghp_new"), &user_target()).unwrap();
        assert_eq!(plan.token_file, "access-tokens = github.com=ghp_new\n");
        assert_eq!(
            plan.nix_conf.as_deref(),
            Some("!include access-tokens.conf\n")
        );
    }

    /// The fast path a shell hook takes on every invocation but the first.
    #[test]
    fn an_already_current_pair_plans_nothing() {
        let plan = plan_injection(
            Some("access-tokens = github.com=ghp_x\n"),
            Some("!include access-tokens.conf\n"),
            &tok("ghp_x"),
            &user_target(),
        );
        assert!(plan.is_none(), "a current pair must not be rewritten");
    }

    #[test]
    fn a_rotated_token_rewrites_the_credential_but_not_the_include() {
        let plan = plan_injection(
            Some("access-tokens = github.com=ghp_old\n"),
            Some("!include access-tokens.conf\n"),
            &tok("ghp_new"),
            &user_target(),
        )
        .unwrap();
        assert_eq!(plan.token_file, "access-tokens = github.com=ghp_new\n");
        assert!(plan.nix_conf.is_none(), "include was already present");
    }

    /// A second forge on the same node must survive. Rewriting the whole line
    /// from one token would delete it, and that surfaces much later as an
    /// unrelated fetch failing.
    #[test]
    fn a_co_resident_host_is_preserved_not_clobbered() {
        let plan = plan_injection(
            Some("access-tokens = gitlab.com=glpat_keep github.com=ghp_old\n"),
            Some("!include access-tokens.conf\n"),
            &tok("ghp_new"),
            &user_target(),
        )
        .unwrap();
        assert!(plan.token_file.contains("gitlab.com=glpat_keep"));
        assert!(plan.token_file.contains("github.com=ghp_new"));
        assert!(!plan.token_file.contains("ghp_old"));
    }

    #[test]
    fn an_existing_nix_conf_is_appended_to_never_replaced() {
        let plan = plan_injection(
            None,
            Some("experimental-features = nix-command flakes\n"),
            &tok("ghp_x"),
            &user_target(),
        )
        .unwrap();
        let conf = plan.nix_conf.unwrap();
        assert!(conf.contains("experimental-features = nix-command flakes"));
        assert!(conf.contains("!include access-tokens.conf"));
    }

    /// A nix.conf missing its trailing newline must not glue the include onto
    /// the previous setting.
    #[test]
    fn a_nix_conf_without_a_trailing_newline_still_gets_a_clean_line() {
        let plan = plan_injection(None, Some("cores = 0"), &tok("ghp_x"), &user_target()).unwrap();
        let conf = plan.nix_conf.unwrap();
        assert!(conf.contains("cores = 0\n!include"), "got: {conf:?}");
    }

    #[test]
    fn a_commented_out_access_tokens_line_is_not_read_as_a_credential() {
        assert_eq!(
            access_tokens_value("# access-tokens = github.com=x\n"),
            None
        );
    }

    /// Trap 1 from the section header, exercised against a real filesystem
    /// because it is the OS behaviour — not our logic — that bites.
    #[test]
    fn a_dangling_symlink_is_cleared_while_a_live_one_is_left_alone() {
        let dir = std::env::temp_dir().join(format!("fleet-dangle-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::write(&target, "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(!clear_dangling(&link).unwrap(), "a LIVE link must survive");
        std::fs::remove_file(&target).unwrap();
        assert!(
            clear_dangling(&link).unwrap(),
            "a DEAD link must be removed so the write can land"
        );
        assert!(std::fs::symlink_metadata(&link).is_err());

        // And a plain absent path is not an error.
        assert!(!clear_dangling(&dir.join("never")).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
