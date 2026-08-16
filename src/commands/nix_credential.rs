//! `fleet nix-credential` — make nix able to authenticate to private
//! pleme-io flake inputs, from wherever a token can be found.
//!
//! ── ★ WHY THIS IS A STANDALONE VERB ─────────────────────────────────
//! [`crate::github_token`] has always known how to FIND a token: env, then
//! nix.conf-shaped files, then SOPS (personal file first, fleet-shared as
//! fallback), across four age-key locations. What it could not do was be
//! CALLED at the moment it is needed.
//!
//! The only caller was `fleet rebuild`, and an operator reaches that through
//! `nix run .#rebuild` — which must first EVALUATE a flake with ~160 private
//! inputs. That evaluation is the thing the credential unblocks, so the brain
//! sat behind the door it exists to open. Every workaround for that has been
//! somebody re-implementing retrieval or injection somewhere else: the nix
//! repo carries 8 retrieval sites and 13 injection sites, and a hand-typed
//! shell one-liner became the fourteenth on plo on 2026-08-16.
//!
//! As its own verb the brain is reachable from a PUBLIC flake reference:
//!
//!     nix run github:pleme-io/fleet -- nix-credential
//!
//! `pleme-io/fleet` is public, so that fetches with no credential at all —
//! which is what makes it a legitimate pre-evaluation hook. The nix repo's
//! `.envrc` calls exactly this, so every nix command run in that repo is
//! authenticated before it starts, `nix run .#rebuild` included.
//!
//! ── DESIGNED TO BE CALLED CONSTANTLY ────────────────────────────────
//! A directory hook runs on every `cd`, so the healthy path must be
//! effectively free. It is: [`github_token::ensure`] plans against the
//! current file contents and returns `AlreadyCurrent` without writing, so a
//! healthy machine costs one stat plus one read. Only a missing, dangling,
//! or rotated credential does any work.
//!
//! No secret ever reaches argv or the environment — the token goes from the
//! decryptor straight into a 0600 file, and only a redacted fingerprint is
//! ever printed.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::github_token::{self, CredentialTarget, Injection};

/// Ensure (or merely report on) the nix GitHub credential.
///
/// * `check` — report only; write nothing. Exits non-zero when no token
///   could be resolved, so it is usable as a gate.
/// * `quiet` — print only when something CHANGED. The mode a shell hook
///   wants: silence on the healthy path, a line when it actually acted.
/// * `root` — target `/root/.config/nix` instead of the caller's own.
///   `sudo` drops `HOME`, so the sudo'd half of a rebuild reads root's config
///   and nothing else; this is how that half gets seeded.
pub fn run(check: bool, quiet: bool, root: bool) -> Result<()> {
    let home = PathBuf::from(std::env::var("HOME").context("HOME is not set")?);
    let user = std::env::var("USER").ok();

    let cwd = std::env::current_dir().context("could not read the current directory")?;
    // A flake root is only needed to locate secrets.yaml for the SOPS
    // fallback. Not being in the repo is therefore not fatal — the env and
    // nix.conf sources still work — so this degrades to the cwd rather than
    // refusing, which matters for a hook that fires in arbitrary directories.
    let flake_root = crate::commands::rebuild::find_flake_root(&cwd).unwrap_or(cwd);

    let target = if root {
        CredentialTarget::root()
    } else {
        CredentialTarget::user(&home)
    };

    if check {
        let env = github_token::system_env();
        let (token, report) = github_token::resolve(&env, &home, &flake_root, user.as_deref());
        match token {
            Some(t) => {
                println!("nix-credential: OK — {} via {}", t.redacted(), t.source.describe());
                Ok(())
            }
            None => {
                for line in &report.lines {
                    eprintln!("{line}");
                }
                anyhow::bail!(
                    "no GitHub token could be resolved — private flake inputs will fail \
                     with HTTP 404 (GitHub hides private repos behind 404, so that is NOT \
                     a missing rev)"
                )
            }
        }
    } else {
        let env = github_token::system_env();
        let report = github_token::ensure(&env, &home, &flake_root, user.as_deref(), &target)
            .map_err(|e| anyhow::anyhow!(e))?;

        for path in &report.cleared {
            eprintln!(
                "nix-credential: removed a DANGLING symlink at {} \
                 (its sops render had evaporated — a reboot wipes the darwin one)",
                path.display()
            );
        }

        match report.injection {
            Injection::AlreadyCurrent => {
                if !quiet {
                    println!(
                        "nix-credential: already current — {} via {}",
                        report.redacted,
                        report.source.describe()
                    );
                }
            }
            Injection::Wrote => {
                println!(
                    "nix-credential: wrote {} — {} via {}",
                    report.target.token_file.display(),
                    report.redacted,
                    report.source.describe()
                );
            }
        }
        Ok(())
    }
}
