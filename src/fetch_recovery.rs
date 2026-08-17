//! Recovery for a flake input the local host cannot fetch.
//!
//! # The class
//!
//! One unfetchable input wedges an entire rebuild. The error surfaces as
//! `error: Failed to open archive (Source threw exception: ... HTTP error 429)`,
//! which names neither the input nor a remedy, so the operator's next move is
//! to guess — and the two obvious guesses are both wrong.
//!
//! # Measured, 2026-08-17 (cid), not assumed
//!
//! A `nix flake update` moved `fenix/rust-analyzer-src` to a rev not yet in the
//! local store. Fetching it 429'd **while `gh api rate_limit` reported
//! 4653/5000 core requests remaining**. So this is NOT the documented 5000/hr
//! API quota: GitHub throttles archive/tarball generation separately, per
//! egress IP, and holding a valid token does not exempt you. The preflight's
//! `nix-access-token` check was green throughout.
//!
//! The two wrong guesses, both ruled out by measurement:
//!
//! - **"retry harder."** nix already backs off — observed `retrying in
//!   143923 ms`, i.e. 2.4 minutes — and still exhausted its attempts. A retry
//!   loop on top of that adds latency, not success. Two full rebuilds died
//!   this way before the cause was understood.
//! - **"pin the input back."** The fleet gate's own error text forbids it, and
//!   it would trade a transient upstream condition for a permanently stale
//!   input.
//!
//! The same prefetch on `rio` (the fleet's always-on `x86_64-linux` builder,
//! different egress) succeeded **immediately**, and `nix copy --from ssh://rio`
//! brought the path over in 43s. That asymmetry is the whole mechanism.
//!
//! # Why sourcing elsewhere is safe rather than a supply-chain hole
//!
//! Because `flake.lock` pins the input's `narHash`, and that hash is what makes
//! an alternate source *checkable* instead of merely convenient. The recovery
//! only accepts a path whose hash equals the one already recorded in the lock,
//! so a second host cannot serve different bytes without being caught — the
//! content is addressed, not trusted. This is ★★ HERMETIC SUPPLY CHAIN's shape
//! (resolve through something we own, verify against a pin), applied to flake
//! inputs. Without the lock comparison this module would be a hole, so
//! [`RecoveryPlan::verify`] is not optional politeness: it is the reason the
//! design is allowed to exist.
//!
//! # Tier honesty
//!
//! **only-mitigated.** Upstream is still tried first and the recovery runs
//! after it fails, so a rebuild on a host with no reachable builder still dies
//! — it just dies with a diagnosis that names the input, the throttle and the
//! remedy instead of an opaque archive error. The destination is the fetch
//! resolving through a fleet-owned mirror *first*, at which point an upstream
//! throttle becomes unobservable rather than recovered-from. Do not read this
//! module as the class being eliminated.

use std::fmt;

/// A GitHub flake input, identified precisely enough to re-fetch elsewhere.
///
/// Deliberately not a bare URL string: the recovery has to hand a *flake ref*
/// to another host, and rebuilding `github:owner/repo/rev` from a URL by string
/// surgery at each call site is how the two spellings drift apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlakeInputRef {
    pub owner: String,
    pub repo: String,
    pub rev: String,
}

impl FlakeInputRef {
    /// Parse the two URL shapes nix uses for a GitHub source.
    ///
    /// Both are accepted because they fail differently and the shape IS the
    /// diagnosis: `/tarball/` is the API endpoint that 429s under the archive
    /// throttle, while `/archive/` is the codeload shape whose 404 means the
    /// credential never arrived. A recovery that understood only one would
    /// silently decline to help with the other.
    pub fn from_source_url(url: &str) -> Option<Self> {
        let rest = url
            .strip_prefix("https://api.github.com/repos/")
            .or_else(|| url.strip_prefix("https://github.com/"))
            .or_else(|| url.strip_prefix("https://codeload.github.com/"))?;

        let mut parts = rest.split('/');
        let owner = parts.next()?;
        let repo = parts.next()?;
        let kind = parts.next()?;
        if kind != "tarball" && kind != "archive" {
            return None;
        }
        let rev_raw = parts.next()?;
        // `/archive/<rev>.tar.gz` carries an extension; `/tarball/<rev>` does not.
        let rev = rev_raw
            .strip_suffix(".tar.gz")
            .or_else(|| rev_raw.strip_suffix(".zip"))
            .unwrap_or(rev_raw);

        if owner.is_empty() || repo.is_empty() || rev.is_empty() {
            return None;
        }
        Some(Self {
            owner: owner.to_string(),
            repo: repo.to_string(),
            rev: rev.to_string(),
        })
    }

    /// The flake ref another host can prefetch. One spelling, one place.
    pub fn flake_ref(&self) -> String {
        let mut s = String::from("github:");
        s.push_str(&self.owner);
        s.push('/');
        s.push_str(&self.repo);
        s.push('/');
        s.push_str(&self.rev);
        s
    }
}

impl fmt::Display for FlakeInputRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.owner, self.repo, short_rev(&self.rev))
    }
}

fn short_rev(rev: &str) -> String {
    rev.chars().take(12).collect()
}

/// Why a source fetch failed, to the precision the remedy depends on.
///
/// Per ★★ kotae these must not render the same bytes: `Throttled` is the
/// upstream refusing to serve content it has, `Unauthorized` is our credential
/// missing, and they have opposite remedies. Collapsing them into "fetch
/// failed" is what sent two rebuilds after the wrong cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchFailure {
    /// 429 / secondary limit. The content exists and another egress can get it.
    Throttled { url: String, input: FlakeInputRef },
    /// 401/403/404 on a private input — a credential problem, NOT a throttle.
    /// Another egress does not help; recovery must decline rather than retry.
    Unauthorized { url: String, input: FlakeInputRef },
}

impl FetchFailure {
    pub fn input(&self) -> &FlakeInputRef {
        match self {
            Self::Throttled { input, .. } | Self::Unauthorized { input, .. } => input,
        }
    }

    /// Whether sourcing from another host can possibly help.
    pub fn recoverable_from_another_egress(&self) -> bool {
        matches!(self, Self::Throttled { .. })
    }
}

/// Classify a failed nix invocation from its stderr.
///
/// Returns `None` when no source-fetch failure is present, which is the common
/// case: an ordinary compile error must NOT be dressed up as a fetch problem.
pub fn classify_fetch_failure(stderr: &str) -> Option<FetchFailure> {
    // Find the line that actually names the URL. nix repeats the failure in a
    // warning, a retry notice and a final error; any of them carries the URL,
    // and taking the first keeps the answer stable across those repetitions.
    let line = stderr
        .lines()
        .find(|l| l.contains("unable to download") || l.contains("Failed to open archive"))?;

    let url = extract_url(line)?;
    let input = FlakeInputRef::from_source_url(&url)?;

    // Scan the WHOLE stderr for the status, not just the URL line: nix prints
    // `HTTP error 429` on the same line but puts the response body several
    // lines later, and a 403 secondary-limit message only appears in the body.
    let throttled = stderr.contains("HTTP error 429")
        || stderr.contains("429: Too Many Requests")
        || stderr.contains("secondary rate limit");
    let unauthorized = stderr.contains("HTTP error 401")
        || stderr.contains("HTTP error 403")
        || stderr.contains("HTTP error 404");

    // Throttle wins a tie: a 403 alongside a 429 is the secondary-limit
    // spelling, and treating it as a credential fault would send the operator
    // to re-provision a token that is fine.
    if throttled {
        Some(FetchFailure::Throttled { url, input })
    } else if unauthorized {
        Some(FetchFailure::Unauthorized { url, input })
    } else {
        None
    }
}

fn extract_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let tail = &line[start..];
    let end = tail
        .find(|c: char| c == '\'' || c == '"' || c == ' ' || c == ')')
        .unwrap_or(tail.len());
    let url = &tail[..end];
    if url.len() > "https://".len() {
        Some(url.to_string())
    } else {
        None
    }
}

/// What to run to recover, and what must hold for the result to be accepted.
///
/// Separated from execution so the decision is unit-testable without a network
/// or a second host: every judgement this module makes is in the pure half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub input: FlakeInputRef,
    pub builder: String,
    /// The narHash `flake.lock` already records. The recovery is only allowed
    /// to accept a path matching this.
    pub expected_nar_hash: String,
}

impl RecoveryPlan {
    /// Build a plan, or decline with the reason.
    ///
    /// Declining is a first-class outcome, not an error: a credential failure
    /// and an unknown expected hash are both cases where trying another host
    /// would either not help or not be verifiable.
    pub fn for_failure(
        failure: &FetchFailure,
        builder: Option<&str>,
        expected_nar_hash: Option<&str>,
    ) -> Result<Self, DeclineReason> {
        if !failure.recoverable_from_another_egress() {
            return Err(DeclineReason::NotAThrottle);
        }
        let builder = builder.ok_or(DeclineReason::NoBuilder)?;
        if builder.trim().is_empty() {
            return Err(DeclineReason::NoBuilder);
        }
        // No pin, no recovery. An unpinned fetch from a second host would be
        // trust, and this module's entire licence to exist is the comparison.
        let hash = expected_nar_hash.ok_or(DeclineReason::NoPinnedHash)?;
        if hash.trim().is_empty() {
            return Err(DeclineReason::NoPinnedHash);
        }
        Ok(Self {
            input: failure.input().clone(),
            builder: builder.to_string(),
            expected_nar_hash: hash.to_string(),
        })
    }

    /// The prefetch argv to run ON the builder.
    pub fn prefetch_argv(&self) -> Vec<String> {
        vec![
            "nix".into(),
            "flake".into(),
            "prefetch".into(),
            "--json".into(),
            self.input.flake_ref(),
        ]
    }

    /// The local argv that pulls the store path across.
    pub fn copy_argv(&self, store_path: &str) -> Vec<String> {
        let mut from = String::from("ssh://");
        from.push_str(&self.builder);
        vec![
            "nix".into(),
            "copy".into(),
            "--from".into(),
            from,
            store_path.into(),
        ]
    }

    /// Accept the builder's result only if its hash equals the lock's pin.
    ///
    /// This is the check that separates a hermetic recovery from a hole.
    pub fn verify(&self, reported_nar_hash: &str) -> Result<(), HashMismatch> {
        if reported_nar_hash == self.expected_nar_hash {
            Ok(())
        } else {
            Err(HashMismatch {
                input: self.input.clone(),
                builder: self.builder.clone(),
                expected: self.expected_nar_hash.clone(),
                got: reported_nar_hash.to_string(),
            })
        }
    }
}

/// Why no recovery was attempted. Each arm has a different operator action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclineReason {
    /// A credential fault. Another egress cannot fix it; fix the token.
    NotAThrottle,
    /// No builder configured or reachable.
    NoBuilder,
    /// The input's hash is not pinned, so an alternate source is unverifiable.
    NoPinnedHash,
}

impl fmt::Display for DeclineReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAThrottle => f.write_str(
                "not a throttle — the upstream refused our CREDENTIAL, and another \
                 egress would be refused identically; fix the token instead",
            ),
            Self::NoBuilder => f.write_str(
                "no fleet builder available to fetch from a different egress",
            ),
            Self::NoPinnedHash => f.write_str(
                "the input's narHash is not pinned in flake.lock, so a path from \
                 another host could not be verified against anything",
            ),
        }
    }
}

/// A builder served content that does not match the lock. Never recoverable —
/// this is the case the hash comparison exists to catch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMismatch {
    pub input: FlakeInputRef,
    pub builder: String,
    pub expected: String,
    pub got: String,
}

impl fmt::Display for HashMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} on {} served narHash {} but flake.lock pins {} — REFUSING the \
             path. Do not \"fix\" this by updating the lock to match: the point \
             of the pin is that two sources must agree.",
            self.input, self.builder, self.got, self.expected
        )
    }
}

/// Read an input's pinned narHash out of a `flake.lock`.
///
/// Matches by rev rather than by node name on purpose: a lock routinely holds
/// several nodes for the same repo (measured on this fleet: three
/// `rust-analyzer-src` nodes, named `_2`/`_3`), so a name lookup would pick an
/// arbitrary one of them and compare against the wrong pin.
pub fn pinned_nar_hash(lock_json: &str, input: &FlakeInputRef) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(lock_json).ok()?;
    let nodes = v.get("nodes")?.as_object()?;
    for node in nodes.values() {
        // `node.get("locked")?` here would be a bug, not a shortcut: inside a
        // loop in an Option-returning fn, `?` abandons the WHOLE search on the
        // first node that lacks the key. `flake.lock` always has such a node —
        // `root` carries only `inputs` — and it sorts first, so the function
        // returned None before examining anything. Skip the node instead.
        let Some(locked) = node.get("locked").and_then(|l| l.as_object()) else {
            continue;
        };
        let matches = locked.get("rev").and_then(|r| r.as_str()) == Some(input.rev.as_str())
            && locked.get("owner").and_then(|o| o.as_str()) == Some(input.owner.as_str())
            && locked.get("repo").and_then(|r| r.as_str()) == Some(input.repo.as_str());
        if matches {
            if let Some(h) = locked.get("narHash").and_then(|h| h.as_str()) {
                return Some(h.to_string());
            }
        }
    }
    None
}

/// What one recovery attempt concluded. Every arm is a different next move,
/// so they must not collapse into a bool.
#[derive(Debug)]
pub enum WarmOutcome {
    /// Every input is in the local store. Nothing was fetched remotely.
    AlreadyWarm,
    /// An input was sourced from a builder and hash-verified against the lock.
    Recovered {
        input: FlakeInputRef,
        builder: String,
        store_path: String,
    },
    /// A fetch failed and recovery was declined, with the reason.
    Declined {
        failure: FetchFailure,
        reason: DeclineReason,
    },
    /// The nix invocation failed for a reason that is not a source fetch.
    /// Deliberately NOT dressed up as a fetch problem.
    NotAFetchProblem { stderr_head: String },
}

/// A remote store that might be able to fetch what we cannot.
///
/// Not every entry in `/etc/nix/machines` is a useful fetch source, which is
/// the non-obvious part: cid declares two builders, and one of them
/// (`linux-builder`) is a **local VM on the same host**, so it egresses from
/// cid's public IP and a per-IP throttle applies to it identically. Asking it
/// to fetch a throttled path is guaranteed to fail. `rio` is remote bare metal
/// and therefore a genuinely different egress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    /// The host as `nix copy --from ssh://<host>` wants it.
    pub host: String,
    /// Whether this builder likely egresses from the same IP as us.
    ///
    /// A heuristic, and deliberately load-bearing for ORDER ONLY: a builder
    /// that shares our egress is tried last rather than excluded, because
    /// correctness comes from the fetch either succeeding or not plus the
    /// narHash comparison — never from this guess being right.
    pub shares_local_egress: bool,
}

/// Parse `/etc/nix/machines` into candidate fetch sources, best first.
pub fn parse_build_machines(contents: &str) -> Vec<Builder> {
    let mut out: Vec<Builder> = contents
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_whitespace().next())
        .filter_map(|uri| {
            let rest = uri
                .strip_prefix("ssh://")
                .or_else(|| uri.strip_prefix("ssh-ng://"))?;
            // Drop any `user@` — `nix copy --from ssh://host` resolves the user
            // through ssh config, and keeping it here would produce two
            // spellings of one builder.
            let host = rest.rsplit('@').next()?;
            if host.is_empty() {
                return None;
            }
            Some(Builder {
                host: host.to_string(),
                shares_local_egress: host_is_local_vm(host),
            })
        })
        .collect();

    out.sort_by_key(|b| b.shares_local_egress);
    out.dedup_by(|a, b| a.host == b.host);
    out
}

/// Known local-VM builder aliases on this fleet. A darwin host runs its
/// `linux-builder` as a VM behind the host's own NAT.
fn host_is_local_vm(host: &str) -> bool {
    host == "linux-builder" || host == "localhost" || host.starts_with("127.")
}

/// What the builder reported for a prefetch. Parsed rather than grepped so a
/// changed field order or added field cannot silently shift the meaning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefetchResult {
    pub store_path: String,
    pub nar_hash: String,
}

/// Read `nix flake prefetch --json` output.
///
/// Named-field access on purpose: this is the value the hash comparison rests
/// on, and a positional/regex read of it would be the weakest link in the
/// chain that makes an alternate source safe.
pub fn parse_prefetch_json(stdout: &str) -> Option<PrefetchResult> {
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).ok()?;
    let store_path = v.get("storePath")?.as_str()?.to_string();
    // `hash` is the top-level narHash of the fetched tree; `locked.narHash`
    // carries the same value. Prefer the explicit one, fall back to locked.
    let nar_hash = v
        .get("hash")
        .and_then(|h| h.as_str())
        .or_else(|| {
            v.get("locked")
                .and_then(|l| l.get("narHash"))
                .and_then(|h| h.as_str())
        })?
        .to_string();
    if store_path.is_empty() || nar_hash.is_empty() {
        return None;
    }
    Some(PrefetchResult {
        store_path,
        nar_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact stderr cid produced, kept verbatim so the parser is tested
    /// against the real shape rather than a tidied reconstruction.
    const REAL_429: &str = "\
warning: error: unable to download 'https://api.github.com/repos/rust-lang/rust-analyzer/tarball/bb3bbbd9e4529cbf1a6392d5953f03eb01af3792': HTTP error 429

       response body:

       429: Too Many Requests
       For more on scraping GitHub and how it may affect your rights, please review our Terms of Service (https://docs.github.com/en/site-policy/github-terms/github-terms-of-service).; retrying in 143923 ms";

    #[test]
    fn classifies_the_real_measured_throttle() {
        let f = classify_fetch_failure(REAL_429).expect("must classify the real stderr");
        assert!(matches!(f, FetchFailure::Throttled { .. }));
        let i = f.input();
        assert_eq!(i.owner, "rust-lang");
        assert_eq!(i.repo, "rust-analyzer");
        assert_eq!(i.rev, "bb3bbbd9e4529cbf1a6392d5953f03eb01af3792");
        assert!(f.recoverable_from_another_egress());
    }

    #[test]
    fn the_terms_of_service_url_does_not_hijack_the_parse() {
        // The response body contains a SECOND https:// URL (GitHub's ToS). If
        // extraction scanned the whole blob instead of the naming line, that
        // docs.github.com link would be parsed as the failing input.
        let f = classify_fetch_failure(REAL_429).unwrap();
        match f {
            FetchFailure::Throttled { url, .. } => {
                assert!(url.contains("rust-analyzer"), "got {url}");
                assert!(!url.contains("docs.github.com"), "ToS URL hijacked the parse");
            }
            _ => panic!("wrong arm"),
        }
    }

    #[test]
    fn an_ordinary_build_error_is_not_a_fetch_failure() {
        // The most important negative: dressing a compile error up as a fetch
        // problem would send every failure to the wrong remedy.
        let stderr = "error[E0432]: unresolved import `foo::bar`\nerror: could not compile `x`";
        assert!(classify_fetch_failure(stderr).is_none());
    }

    #[test]
    fn a_credential_failure_is_a_distinct_arm_and_declines_recovery() {
        let stderr = "warning: error: unable to download \
            'https://api.github.com/repos/pleme-io/secret/tarball/abc123': HTTP error 404";
        let f = classify_fetch_failure(stderr).expect("must classify");
        assert!(matches!(f, FetchFailure::Unauthorized { .. }));
        assert!(
            !f.recoverable_from_another_egress(),
            "another egress cannot fix a credential fault"
        );
        assert_eq!(
            RecoveryPlan::for_failure(&f, Some("rio"), Some("sha256-x")),
            Err(DeclineReason::NotAThrottle)
        );
    }

    #[test]
    fn a_403_alongside_a_429_reads_as_the_throttle() {
        // GitHub spells the secondary limit both ways. Reading it as a
        // credential fault would send the operator to re-provision a good token.
        let stderr = "unable to download 'https://api.github.com/repos/o/r/tarball/deadbeef': \
            HTTP error 403\n429: Too Many Requests";
        assert!(matches!(
            classify_fetch_failure(stderr),
            Some(FetchFailure::Throttled { .. })
        ));
    }

    #[test]
    fn both_url_shapes_parse_and_agree_on_the_ref() {
        let a = FlakeInputRef::from_source_url(
            "https://api.github.com/repos/rust-lang/rust-analyzer/tarball/bb3bbbd9",
        )
        .unwrap();
        let b = FlakeInputRef::from_source_url(
            "https://github.com/rust-lang/rust-analyzer/archive/bb3bbbd9.tar.gz",
        )
        .unwrap();
        assert_eq!(a, b, "the /tarball/ and /archive/ shapes name the same input");
        assert_eq!(a.flake_ref(), "github:rust-lang/rust-analyzer/bb3bbbd9");
    }

    #[test]
    fn a_non_source_github_url_is_not_an_input() {
        assert!(FlakeInputRef::from_source_url("https://github.com/o/r/issues/5").is_none());
        assert!(FlakeInputRef::from_source_url("https://example.com/x/y/tarball/z").is_none());
    }

    #[test]
    fn recovery_refuses_without_a_pinned_hash() {
        let f = classify_fetch_failure(REAL_429).unwrap();
        assert_eq!(
            RecoveryPlan::for_failure(&f, Some("rio"), None),
            Err(DeclineReason::NoPinnedHash),
            "an unverifiable alternate source must be refused, not attempted"
        );
        assert_eq!(
            RecoveryPlan::for_failure(&f, None, Some("sha256-x")),
            Err(DeclineReason::NoBuilder)
        );
    }

    #[test]
    fn verify_accepts_only_the_locks_hash() {
        let f = classify_fetch_failure(REAL_429).unwrap();
        let plan = RecoveryPlan::for_failure(&f, Some("rio"), Some("sha256-GOOD=")).unwrap();
        assert!(plan.verify("sha256-GOOD=").is_ok());

        let err = plan.verify("sha256-EVIL=").expect_err("a mismatch must be refused");
        let msg = err.to_string();
        assert!(msg.contains("REFUSING"), "got {msg}");
        assert!(
            msg.contains("two sources must agree"),
            "the message must forbid 'fix the lock to match', got {msg}"
        );
    }

    #[test]
    fn argv_is_a_list_and_names_the_builder_once() {
        let f = classify_fetch_failure(REAL_429).unwrap();
        let plan = RecoveryPlan::for_failure(&f, Some("rio"), Some("sha256-GOOD=")).unwrap();
        assert_eq!(
            plan.prefetch_argv(),
            vec![
                "nix",
                "flake",
                "prefetch",
                "--json",
                "github:rust-lang/rust-analyzer/bb3bbbd9e4529cbf1a6392d5953f03eb01af3792"
            ]
        );
        assert_eq!(
            plan.copy_argv("/nix/store/abc-source"),
            vec!["nix", "copy", "--from", "ssh://rio", "/nix/store/abc-source"]
        );
    }

    /// The lock shape that actually broke a name-based lookup: three nodes for
    /// one repo at three different revs.
    const MULTI_NODE_LOCK: &str = r#"{
      "nodes": {
        "rust-analyzer-src":   { "locked": { "owner":"rust-lang","repo":"rust-analyzer","rev":"bb3bbbd9","narHash":"sha256-FIRST=","type":"github" } },
        "rust-analyzer-src_2": { "locked": { "owner":"rust-lang","repo":"rust-analyzer","rev":"a9a66c40","narHash":"sha256-SECOND=","type":"github" } },
        "rust-analyzer-src_3": { "locked": { "owner":"rust-lang","repo":"rust-analyzer","rev":"c5d30e23","narHash":"sha256-THIRD=","type":"github" } },
        "root":                { "inputs": { "x": "y" } }
      }
    }"#;

    /// cid's real `/etc/nix/machines`, verbatim.
    const REAL_MACHINES: &str = "\
ssh://root@rio x86_64-linux /var/root/.ssh/nix_builder_ed25519 16 16 nixos-test,benchmark,big-parallel,kvm - -
ssh-ng://builder@linux-builder aarch64-linux,x86_64-linux /etc/nix/builder_ed25519 4 1 kvm,benchmark,big-parallel - c3NoLWVk";

    /// rio's real `nix flake prefetch --json` output, byte-for-byte, captured
    /// 2026-08-17. Note `locked` carries NO `narHash` — the hash lives only in
    /// the top-level `hash` field, so a reader that looked only inside `locked`
    /// would find nothing and report the recovery unverifiable.
    const REAL_PREFETCH: &str = r#"{"hash":"sha256-AxaCvcUZIgkNvzxDY85k7ICuGaWNbrVuGUn6SxLS+V0=","locked":{"lastModified":1786897424,"owner":"rust-lang","repo":"rust-analyzer","rev":"bb3bbbd9e4529cbf1a6392d5953f03eb01af3792","type":"github"},"original":{"owner":"rust-lang","repo":"rust-analyzer","rev":"bb3bbbd9e4529cbf1a6392d5953f03eb01af3792","type":"github"},"storePath":"/nix/store/lnq4dmza47mv6zjnw5ijp7c55s6nyzqr-source"}"#;

    #[test]
    fn parses_the_real_builder_prefetch_output() {
        let r = parse_prefetch_json(REAL_PREFETCH).expect("must parse rio's real output");
        assert_eq!(
            r.store_path,
            "/nix/store/lnq4dmza47mv6zjnw5ijp7c55s6nyzqr-source"
        );
        assert_eq!(r.nar_hash, "sha256-AxaCvcUZIgkNvzxDY85k7ICuGaWNbrVuGUn6SxLS+V0=");
    }

    #[test]
    fn the_real_builder_hash_equals_the_real_lock_pin() {
        // The end-to-end property, on measured bytes from both sides: what rio
        // served equals what this fleet's flake.lock pinned. This is the whole
        // safety argument for sourcing from another host, so it is asserted on
        // real values rather than reasoned about.
        let r = parse_prefetch_json(REAL_PREFETCH).unwrap();
        let f = classify_fetch_failure(REAL_429).unwrap();
        let plan = RecoveryPlan::for_failure(
            &f,
            Some("rio"),
            // the value flake.lock records for rust-analyzer-src
            Some("sha256-AxaCvcUZIgkNvzxDY85k7ICuGaWNbrVuGUn6SxLS+V0="),
        )
        .unwrap();
        assert!(
            plan.verify(&r.nar_hash).is_ok(),
            "rio's bytes must satisfy the lock's pin"
        );
    }

    #[test]
    fn garbage_prefetch_output_is_declined_not_guessed() {
        assert!(parse_prefetch_json("").is_none());
        assert!(parse_prefetch_json("not json").is_none());
        assert!(parse_prefetch_json(r#"{"storePath":""}"#).is_none());
        // A path with no hash must NOT be accepted: an unverifiable path is
        // exactly what the design forbids.
        assert!(parse_prefetch_json(r#"{"storePath":"/nix/store/x-source"}"#).is_none());
    }

    #[test]
    fn the_remote_builder_is_preferred_over_the_local_vm() {
        let b = parse_build_machines(REAL_MACHINES);
        assert_eq!(b.len(), 2);
        // rio first: a local VM shares this host's egress IP, so asking it to
        // fetch a per-IP-throttled path is guaranteed to fail.
        assert_eq!(b[0].host, "rio");
        assert!(!b[0].shares_local_egress);
        assert_eq!(b[1].host, "linux-builder");
        assert!(
            b[1].shares_local_egress,
            "linux-builder is a VM on this host — it is NOT a different egress"
        );
    }

    #[test]
    fn the_user_prefix_is_dropped_so_one_builder_has_one_spelling() {
        let b = parse_build_machines("ssh://root@rio x86_64-linux - 8 1 - - -");
        assert_eq!(b[0].host, "rio", "user@ must not become part of the host");
    }

    #[test]
    fn comments_blanks_and_unknown_schemes_are_ignored() {
        let b = parse_build_machines(
            "# a comment\n\n  \nssh://root@rio x86_64-linux\nlocal ?\ndaemon x86_64-linux\n",
        );
        assert_eq!(
            b.iter().map(|x| x.host.as_str()).collect::<Vec<_>>(),
            vec!["rio"],
            "only ssh/ssh-ng entries are reachable fetch sources"
        );
    }

    #[test]
    fn pinned_hash_is_found_by_rev_not_by_node_name() {
        let want = FlakeInputRef {
            owner: "rust-lang".into(),
            repo: "rust-analyzer".into(),
            rev: "a9a66c40".into(),
        };
        assert_eq!(
            pinned_nar_hash(MULTI_NODE_LOCK, &want).as_deref(),
            Some("sha256-SECOND="),
            "three nodes name this repo; the rev must pick the right pin"
        );
    }

    #[test]
    fn an_absent_input_has_no_pin_rather_than_a_wrong_one() {
        let missing = FlakeInputRef {
            owner: "rust-lang".into(),
            repo: "rust-analyzer".into(),
            rev: "0000dead".into(),
        };
        assert_eq!(pinned_nar_hash(MULTI_NODE_LOCK, &missing), None);

        // This assertion is the one that matters, and the reason the test is
        // written in this order: the None above is only meaningful if the scan
        // actually RAN. As first written it passed while `pinned_nar_hash`
        // returned None for every input — a `?` on the keyless `root` node
        // abandoned the search before reading a single pin — so the negative
        // was true by accident. Pairing it with a positive lookup over the SAME
        // lock is what makes the absence a finding instead of a blind spot.
        let present = FlakeInputRef {
            owner: "rust-lang".into(),
            repo: "rust-analyzer".into(),
            rev: "bb3bbbd9".into(),
        };
        assert_eq!(
            pinned_nar_hash(MULTI_NODE_LOCK, &present).as_deref(),
            Some("sha256-FIRST="),
            "a lock containing a keyless `root` node must still be searchable"
        );
    }
}
