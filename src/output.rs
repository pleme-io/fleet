//! The output policy: fleet prints only what the operator must see or act on.
//!
//! ── ★ ONE TYPE, BOTH ENDS ───────────────────────────────────────────────
//! [`Level`] is at once the class a message is written at and the threshold a
//! run prints at. A message shows when its level is at or below the threshold,
//! so the two can never disagree about what a level means.
//!
//! - [`Level::Required`] — errors and the actual cause of a failure, warnings
//!   that need an action, a prompt, and the final one-line result.
//! - [`Level::Verbose`] — everything else: progress narration, a restatement of
//!   a default or of what was detected, "skipped because not configured".
//!
//! Nothing was deleted to get here. Every message fleet printed before this
//! policy existed still exists, word for word, at one of the two levels, so
//! `--verbose` gives back exactly the old output (★★ configured off, never
//! deleted). The logging helpers take the level as a parameter rather than
//! each call site wrapping itself in an `if`, which makes the classification
//! compulsory: a new message cannot compile without choosing one.
//!
//! Resolution order, most specific wins: `--verbose` / `-v`, then
//! `FLEET_OUTPUT=required|verbose`, then `output.level` in `fleet.yaml`, then
//! the default, [`Level::Required`].

use colored::Colorize;
use std::cell::RefCell;
use std::sync::atomic::{AtomicU8, Ordering};

/// How much fleet prints. Ordered: `Required < Verbose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Level {
    /// What the operator must see or act on. The default.
    #[default]
    Required,
    /// Progress narration and detected/default restatements as well.
    Verbose,
}

impl Level {
    /// Every level, in order. The tests walk this so a new level cannot land
    /// without a row.
    pub const ALL: [Level; 2] = [Level::Required, Level::Verbose];

    /// The spelling used by `FLEET_OUTPUT` and `output.level`.
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Required => "required",
            Level::Verbose => "verbose",
        }
    }

    /// Parse the config/env spelling. `None` names an unknown value, which
    /// the caller reports and ignores: a typo in one key must not take the
    /// rest of `fleet.yaml` down with it.
    pub fn parse(s: &str) -> Option<Level> {
        Level::ALL
            .into_iter()
            .find(|l| l.as_str().eq_ignore_ascii_case(s.trim()))
    }

    /// Does a message written at `self` print when the run is at `threshold`?
    pub fn shows_at(self, threshold: Level) -> bool {
        self <= threshold
    }
}

/// Where the threshold came from, so an ignored value can be named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub level: Level,
    /// Values that were present but not a level, as `(source, value)`.
    pub rejected: Vec<(&'static str, String)>,
}

/// Resolve the run's threshold from its three sources. Pure, so the order is
/// testable without touching the process environment.
pub fn resolve(flag_verbose: bool, env: Option<&str>, config: Option<&str>) -> Resolved {
    let mut rejected = Vec::new();
    let mut pick = |source: &'static str, raw: Option<&str>| -> Option<Level> {
        let raw = raw?;
        let parsed = Level::parse(raw);
        if parsed.is_none() {
            rejected.push((source, raw.to_owned()));
        }
        parsed
    };
    let from_env = pick("FLEET_OUTPUT", env);
    let from_config = pick("output.level in fleet.yaml", config);
    let level = if flag_verbose {
        Level::Verbose
    } else {
        from_env.or(from_config).unwrap_or_default()
    };
    Resolved { level, rejected }
}

static THRESHOLD: AtomicU8 = AtomicU8::new(0);

/// Set the process-wide threshold. Called once, from `main`.
pub fn set_threshold(level: Level) {
    THRESHOLD.store(level as u8, Ordering::Relaxed);
}

/// The process-wide threshold.
pub fn threshold() -> Level {
    match THRESHOLD.load(Ordering::Relaxed) {
        0 => Level::Required,
        _ => Level::Verbose,
    }
}

/// The four message kinds fleet has always printed, with their prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Info,
    Success,
    Warning,
    Error,
}

/// Which stream a kind goes to. Unchanged from before the policy: errors on
/// stderr, everything else on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

impl Kind {
    pub fn stream(self) -> Stream {
        match self {
            Kind::Error => Stream::Stderr,
            _ => Stream::Stdout,
        }
    }
}

/// The exact line a message renders to — the pre-policy format, byte for byte.
pub fn render(kind: Kind, msg: &str) -> String {
    let prefix = match kind {
        Kind::Info => "[INFO]".blue().bold(),
        Kind::Success => "[OK]".green().bold(),
        Kind::Warning => "[WARN]".yellow().bold(),
        Kind::Error => "[ERROR]".red().bold(),
    };
    format!("{prefix} {msg}")
}

/// A captured emission: the stream it went to and the rendered line.
pub type Captured = (Stream, String);

thread_local! {
    /// When set, emissions on this thread are recorded against the given
    /// threshold instead of printed. Thread-local so parallel tests cannot see
    /// each other's output or thresholds.
    static CAPTURE: RefCell<Option<(Level, Vec<Captured>)>> = const { RefCell::new(None) };
}

#[cfg(test)]
/// Run `f` with this thread's output captured at `threshold`, returning what
/// would have been printed.
pub fn capture(threshold: Level, f: impl FnOnce()) -> Vec<Captured> {
    CAPTURE.with(|c| *c.borrow_mut() = Some((threshold, Vec::new())));
    f();
    CAPTURE.with(|c| c.borrow_mut().take().map(|(_, v)| v).unwrap_or_default())
}

/// Print raw text (no prefix) at `level` — for multi-line blocks that belong
/// to a message, such as a report's rows.
pub fn emit_raw(level: Level, stream: Stream, text: &str) {
    emit_line(level, stream, text.to_owned());
}

fn emit_line(level: Level, stream: Stream, line: String) {
    let captured = CAPTURE.with(|c| {
        let mut c = c.borrow_mut();
        match c.as_mut() {
            Some((threshold, sink)) => {
                if level.shows_at(*threshold) {
                    sink.push((stream, line.clone()));
                }
                true
            }
            None => false,
        }
    });
    if captured || !level.shows_at(threshold()) {
        return;
    }
    match stream {
        Stream::Stdout => println!("{line}"),
        Stream::Stderr => eprintln!("{line}"),
    }
}

/// Emit one message of `kind` at `level`.
pub fn emit(level: Level, kind: Kind, msg: &str) {
    emit_line(level, kind.stream(), render(kind, msg));
}

pub fn log_info(level: Level, msg: &str) {
    emit(level, Kind::Info, msg);
}

pub fn log_success(level: Level, msg: &str) {
    emit(level, Kind::Success, msg);
}

pub fn log_warning(level: Level, msg: &str) {
    emit(level, Kind::Warning, msg);
}

/// Errors are always required: there is no level at which a failure is noise.
pub fn log_error(msg: &str) {
    emit(Level::Required, Kind::Error, msg);
}

/// Should a top-level error carry its backtrace?
///
/// Only when asked for — by `--verbose` or by `RUST_LIB_BACKTRACE=1`, anyhow's
/// own switch. Ambient `RUST_BACKTRACE=1` deliberately does NOT count: the
/// fleet's Rust devshells export it session-wide (measured 2026-09-29 in the
/// operator's shell), so honouring it meant every failed rebuild ended in a
/// page of frames that pushed nix's real error off the screen.
pub fn wants_backtrace(threshold: Level, rust_lib_backtrace: Option<&str>) -> bool {
    threshold == Level::Verbose || rust_lib_backtrace.is_some_and(|v| v != "0")
}

/// Render a top-level error: a failed command's own error lines first, then
/// one line with the message and its cause chain, then the backtrace only when
/// [`wants_backtrace`] says so. The verdict is the last line on screen unless
/// a backtrace was asked for.
pub fn render_error(err: &anyhow::Error, backtrace: bool) -> String {
    let mut out = String::new();
    let failed = err
        .chain()
        .find_map(|e| e.downcast_ref::<crate::commands::utils::CommandFailed>());
    if let Some(f) = failed {
        for line in &f.cause {
            out.push_str("  ");
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(&render(Kind::Error, &format!("{err:#}")));
    if backtrace {
        let bt = err.backtrace();
        if bt.status() == std::backtrace::BacktraceStatus::Captured {
            out.push_str("\n\nStack backtrace:\n");
            out.push_str(&bt.to_string());
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Drop ANSI colour so assertions read as text whatever `colored` decided
    /// about this terminal. Never flips `colored`'s global override, which
    /// would race the byte-identity test running beside it.
    pub(crate) fn plain(c: &[Captured]) -> Vec<String> {
        c.iter().map(|(_, l)| strip_ansi(l)).collect()
    }

    pub(crate) fn strip_ansi(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut it = s.chars().peekable();
        while let Some(ch) = it.next() {
            if ch == '\u{1b}' && it.peek() == Some(&'[') {
                it.next();
                for c in it.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }

    /// Every message kind at both levels. Texts are the operator's own
    /// complaint, verbatim, plus the lines that must survive the default.
    fn sample() {
        log_info(Level::Verbose, "Node: ryn (from hostname)");
        log_info(Level::Verbose, "GitHub token: $GITHUB_TOKEN");
        log_info(Level::Verbose, "Darwin rebuild for ryn...");
        log_info(
            Level::Verbose,
            "e2e gate: no .#e2e-mado app in this flake — skipped",
        );
        log_warning(
            Level::Required,
            "e2e gate SKIPPED via FLEET_SKIP_E2E_GATE=1",
        );
        log_success(Level::Required, "ryn rebuilt successfully");
        log_error("rebuild failed");
    }

    #[test]
    fn required_shows_only_warnings_results_and_errors() {
        assert_eq!(
            plain(&capture(Level::Required, sample)),
            vec![
                "[WARN] e2e gate SKIPPED via FLEET_SKIP_E2E_GATE=1",
                "[OK] ryn rebuilt successfully",
                "[ERROR] rebuild failed",
            ]
        );
    }

    #[test]
    fn verbose_shows_every_message() {
        assert_eq!(
            plain(&capture(Level::Verbose, sample)),
            vec![
                "[INFO] Node: ryn (from hostname)",
                "[INFO] GitHub token: $GITHUB_TOKEN",
                "[INFO] Darwin rebuild for ryn...",
                "[INFO] e2e gate: no .#e2e-mado app in this flake — skipped",
                "[WARN] e2e gate SKIPPED via FLEET_SKIP_E2E_GATE=1",
                "[OK] ryn rebuilt successfully",
                "[ERROR] rebuild failed",
            ]
        );
    }

    /// `--verbose` must give back exactly the pre-policy output: the same
    /// prefix, colour, text and stream as the old `log_*` helpers. The
    /// expected lines below ARE the old helpers' bodies.
    #[test]
    fn verbose_output_is_byte_identical_to_the_old_helpers() {
        let m = "Node: ryn (from hostname)";
        let got = capture(Level::Verbose, || {
            log_info(Level::Verbose, m);
            log_success(Level::Verbose, m);
            log_warning(Level::Verbose, m);
            log_error(m);
        });
        let want = vec![
            (Stream::Stdout, format!("{} {}", "[INFO]".blue().bold(), m)),
            (Stream::Stdout, format!("{} {}", "[OK]".green().bold(), m)),
            (
                Stream::Stdout,
                format!("{} {}", "[WARN]".yellow().bold(), m),
            ),
            (Stream::Stderr, format!("{} {}", "[ERROR]".red().bold(), m)),
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn every_level_is_ordered_and_round_trips() {
        for l in Level::ALL {
            assert_eq!(Level::parse(l.as_str()), Some(l));
            assert!(Level::Required.shows_at(l), "required shows at every level");
        }
        assert!(!Level::Verbose.shows_at(Level::Required));
    }

    #[test]
    fn resolution_order_is_flag_then_env_then_config_then_default() {
        assert_eq!(resolve(false, None, None).level, Level::Required);
        assert_eq!(resolve(false, None, Some("verbose")).level, Level::Verbose);
        assert_eq!(
            resolve(false, Some("required"), Some("verbose")).level,
            Level::Required
        );
        assert_eq!(resolve(true, Some("required"), None).level, Level::Verbose);
        // An unknown value is named and ignored, never fatal.
        let r = resolve(false, Some("loud"), Some("verbose"));
        assert_eq!(r.level, Level::Verbose);
        assert_eq!(r.rejected, vec![("FLEET_OUTPUT", "loud".to_owned())]);
    }

    #[test]
    fn backtrace_needs_verbose_or_the_library_switch_not_ambient_rust_backtrace() {
        assert!(!wants_backtrace(Level::Required, None));
        assert!(!wants_backtrace(Level::Required, Some("0")));
        assert!(wants_backtrace(Level::Required, Some("1")));
        assert!(wants_backtrace(Level::Verbose, None));
    }

    #[test]
    fn a_default_error_prints_its_cause_chain_and_no_backtrace() {
        let err = anyhow::anyhow!("inner").context("outer");
        let quiet = strip_ansi(&render_error(&err, false));
        assert_eq!(quiet, "[ERROR] outer: inner");
        let loud = strip_ansi(&render_error(&err, true));
        assert!(loud.starts_with(&quiet), "{loud}");
    }
}
