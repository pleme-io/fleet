//! `fleet mcp` — the convergence document over MCP.
//!
//! ── ★ A TRANSPORT, NOT A SECOND SOURCE OF TRUTH ─────────────────────────
//! Every tool here delegates to [`super::convergence`]. There is exactly
//! one place in this fleet that decides what "converged" means, and an MCP
//! server that re-derived the verdict would be a fifth definition — the
//! precise failure that made the old surfaces disagree, where an operator
//! learns to trust whichever one is quietest.
//!
//! So this file owns wire shape and nothing else: no thresholds, no
//! staleness budget, no verdict vocabulary. If a rule is missing, it is
//! missing from `convergence.rs` and belongs there.
//!
//! ── ★ WHY THE OPERATOR ASKED FOR THIS ───────────────────────────────────
//! An agent has no preattentive vision: it cannot glance at a prompt and
//! notice a red segment the way a human does. `fleet convergence` answers
//! the question for a human at a terminal; this answers it for an agent
//! reasoning about the fleet, from the same bytes. Both read what the
//! reconciler PUBLISHED, so neither needs to reach a node — which is what
//! makes the answer correct for a machine that is off tailscale or whose
//! daemon is dead.

use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router, ServerHandler,
};
use serde::Deserialize;

/// Input for `gitops_convergence`. Empty: the document describes THIS
/// node, and there is deliberately no `node` parameter — accepting one
/// would imply this server can answer for a remote host, which it cannot
/// and must not pretend to.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConvergenceInput {}

#[derive(Clone)]
pub struct FleetMcp {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl FleetMcp {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Is this node reconciled with its branch, and when did it last try?
    #[tool(description = "Report this node's GitOps convergence: verdict \
                       (converged/behind/ineffective/stopped/failing/unknown/\
                       notEnrolled), the deployed rev, the branch HEAD the \
                       reconciler last observed, and how long ago it ticked. \
                       Reads state the reconciler published to disk, so it \
                       answers correctly even when the daemon is dead — a \
                       stopped loop reports `stopped`, never silence. A loop \
                       that is pulsing on schedule while resolving no branch \
                       HEAD reports `ineffective`: alive is not the same as \
                       working, and a fresh heartbeat proves only the former.")]
    async fn gitops_convergence(
        &self,
        Parameters(ConvergenceInput {}): Parameters<ConvergenceInput>,
    ) -> String {
        let node =
            super::utils::run_command_output(std::process::Command::new("hostname").arg("-s"))
                .unwrap_or_else(|_| "unknown".to_owned());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let doc = super::convergence::local(
            std::path::Path::new(super::convergence::DEFAULT_STATE_DIR),
            node,
            now,
        );
        // Serialization failure is reported AS a document rather than as an
        // empty string: a tool that returns nothing is indistinguishable
        // from a healthy silence, which is the whole class this fleet has
        // been closing.
        serde_json::to_string_pretty(&doc).unwrap_or_else(|e| {
            let mut s = String::from("{\"error\":\"could not serialize convergence document: ");
            s.push_str(&e.to_string());
            s.push_str("\"}");
            s
        })
    }
}

impl Default for FleetMcp {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for FleetMcp {
    fn get_info(&self) -> ServerInfo {
        // rmcp 1.x marks ServerInfo #[non_exhaustive], so a struct expression
        // is forbidden outside its crate — default-then-mutate is the
        // sanctioned construction (the same shape tend's server already uses).
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.instructions = Some(
            "fleet — GitOps convergence for the node this server runs on. \
             `gitops_convergence` reads the reconciler's published heartbeat \
             and receipt chain; it never reaches a remote host, so a node \
             that is unreachable is not thereby reported unhealthy, and a \
             node whose daemon has died still reports its last known state \
             plus how stale that state is. Absent evidence returns the \
             verdict `unknown` — it is never rounded to `converged`, and a \
             tick still running returns `unknown` too rather than claiming a \
             result that has not happened yet. Evidence that is PRESENT and \
             bad is not an unknown: a loop whose last finished tick resolved \
             no branch HEAD returns `ineffective` — pulsing on schedule while \
             doing no convergence work — which is a distinct state from both \
             `converged` and a dead loop's `stopped`."
                .to_owned(),
        );
        info
    }
}

/// Serve on stdio — the transport every pleme-io MCP consumer speaks.
pub fn mcp() -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        use rmcp::ServiceExt as _;
        let service = FleetMcp::new()
            .serve(rmcp::transport::stdio())
            .await
            .map_err(|e| anyhow::anyhow!("fleet mcp: serve failed: {e}"))?;
        service
            .waiting()
            .await
            .map_err(|e| anyhow::anyhow!("fleet mcp: {e}"))?;
        Ok::<_, anyhow::Error>(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The server must advertise tools, or a client sees a server with
    /// nothing to offer and the wiring failure looks like an empty fleet.
    #[test]
    fn the_server_advertises_a_tool_capability() {
        let info = FleetMcp::new().get_info();
        assert!(info.capabilities.tools.is_some(), "no tools advertised");
        let instr = info.instructions.expect("instructions guide the agent");
        // The two properties an agent MUST know to read the output
        // correctly, asserted so a future edit cannot quietly drop them.
        assert!(
            instr.contains("unknown"),
            "the unknown verdict must be documented"
        );
        // rio, 2026-08-05: a fresh pulse with `head_rev: null` every 60s for
        // an hour. An agent reading this tool must know that state has its
        // own word, or it will read the absence of `stopped` as health.
        assert!(
            instr.contains("ineffective"),
            "the ineffective verdict must be documented"
        );
        assert!(
            instr.contains("never reaches a remote host"),
            "an agent must not read this as a fleet-wide answer"
        );
    }

    /// The tool returns the SAME document `fleet convergence --json`
    /// prints. Pinned because the moment they diverge, an operator and an
    /// agent are debugging different fleets.
    #[tokio::test]
    async fn the_tool_returns_the_convergence_document() {
        let out = FleetMcp::new()
            .gitops_convergence(Parameters(ConvergenceInput {}))
            .await;
        let v: serde_json::Value =
            serde_json::from_str(&out).expect("the tool must emit valid JSON");
        assert!(v["node"].is_string(), "document must name the node: {out}");
        assert!(
            v["verdict"].is_string(),
            "document must carry a verdict: {out}"
        );
    }
}
