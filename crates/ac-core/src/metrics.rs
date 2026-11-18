//! Native Prometheus 0.0.4 metrics and OpenTelemetry export engine (Feature F12).
//!
//! Provides a centralized `MetricsCollector` that gathers metrics from:
//! - `SessionManager`: session counts, states, crashes, restarts, durations.
//! - `InteractionHub`: interaction counts by decision, pending count, approval latency.
//! - `AccountManager`: account counts by provider, concurrency caps, active sessions.
//! - `EventStore`: total sequence events count.
//!
//! Exposes:
//! - Standard Prometheus text format (version 0.0.4) with `# HELP` and `# TYPE`.
//! - Structured JSON representation.
//! - Lightweight HTTP server serving `GET /metrics`, `GET /health`, and `GET /livez`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;

use crate::account_manager::AccountManagerHandle;
use crate::interaction_hub::InteractionHubHandle;
use crate::session::manager::SessionManagerHandle;
use crate::types::{AgentEvent, EventKind, InteractionState, PolicyDecision, SessionState};

/// Standard histogram bucket thresholds for session execution duration (in seconds).
pub const SESSION_DURATION_BUCKETS: &[f64] = &[
    10.0, 30.0, 60.0, 300.0, 600.0, 1800.0, 3600.0,
];

/// Standard histogram bucket thresholds for interaction approval latency (in seconds).
pub const APPROVAL_LATENCY_BUCKETS: &[f64] = &[
    0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 300.0,
];

/// Snapshot of a Prometheus histogram metric.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramSnapshot {
    pub count: u64,
    pub sum: f64,
    pub buckets: Vec<(f64, u64)>, // (le, cumulative_count)
}

impl HistogramSnapshot {
    pub fn new(thresholds: &[f64], values: &[f64]) -> Self {
        let count = values.len() as u64;
        let sum = values.iter().sum::<f64>();

        let mut buckets = Vec::with_capacity(thresholds.len());
        for &le in thresholds {
            let cumulative = values.iter().filter(|&&v| v <= le).count() as u64;
            buckets.push((le, cumulative));
        }

        Self {
            count,
            sum,
            buckets,
        }
    }
}

/// Snapshot of an account concurrency cap and active session load.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountCapSnapshot {
    pub account_id: String,
    pub label: String,
    pub provider: String,
    pub concurrency_cap: u8,
    pub active_sessions: u8,
}

/// Comprehensive point-in-time metrics snapshot across all AgentControl subsystems.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DaemonMetricsSnapshot {
    pub timestamp: String,
    pub version: String,
    pub sessions_total: u64,
    pub sessions_active_by_state: HashMap<String, u64>,
    pub session_crashes_total: u64,
    pub session_restarts_total: u64,
    pub session_duration_seconds: HistogramSnapshot,
    pub interactions_total_by_decision: HashMap<String, u64>,
    pub interactions_pending: u64,
    pub approval_latency_seconds: HistogramSnapshot,
    pub accounts_total_by_provider: HashMap<String, u64>,
    pub account_concurrency_caps: Vec<AccountCapSnapshot>,
    pub events_total: u64,
}

/// Internal atomic state for counters that accumulate across lifecycle events.
struct MetricsState {
    sessions_created: AtomicU64,
    session_crashes: AtomicU64,
    session_restarts: AtomicU64,
    events_total: AtomicU64,
}

/// Collector responsible for scraping subsystem state and compiling metrics snapshots.
#[derive(Clone)]
pub struct MetricsCollector {
    session_mgr: SessionManagerHandle,
    account_mgr: Option<AccountManagerHandle>,
    interaction_hub: Option<InteractionHubHandle>,
    state: Arc<MetricsState>,
}

impl MetricsCollector {
    /// Create a new metrics collector bound to subsystem handles.
    pub fn new(
        session_mgr: SessionManagerHandle,
        account_mgr: Option<AccountManagerHandle>,
        interaction_hub: Option<InteractionHubHandle>,
    ) -> Self {
        Self {
            session_mgr,
            account_mgr,
            interaction_hub,
            state: Arc::new(MetricsState {
                sessions_created: AtomicU64::new(0),
                session_crashes: AtomicU64::new(0),
                session_restarts: AtomicU64::new(0),
                events_total: AtomicU64::new(0),
            }),
        }
    }

    /// Subscribe to the broadcast event stream to track cumulative counters in real time.
    pub fn with_event_bus(self, mut event_rx: broadcast::Receiver<AgentEvent>) -> Self {
        let state = Arc::clone(&self.state);
        tokio::spawn(async move {
            while let Ok(event) = event_rx.recv().await {
                state.events_total.fetch_max(event.seq, Ordering::Relaxed);
                match event.kind {
                    EventKind::SessionCreated => {
                        state.sessions_created.fetch_add(1, Ordering::Relaxed);
                    }
                    EventKind::SessionCrashed => {
                        state.session_crashes.fetch_add(1, Ordering::Relaxed);
                    }
                    EventKind::SessionRestartAttempted => {
                        state.session_restarts.fetch_add(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        });
        self
    }

    /// Subscribe to the broadcast event sender channel.
    pub fn with_event_channel(self, event_tx: &broadcast::Sender<AgentEvent>) -> Self {
        self.with_event_bus(event_tx.subscribe())
    }

    /// Gather current metrics snapshot from all subsystems.
    pub async fn gather(&self) -> Result<DaemonMetricsSnapshot, anyhow::Error> {
        let now = Utc::now();

        // 1. Session Manager state
        let sessions = self.session_mgr.list().await.unwrap_or_default();

        let mut sessions_active_by_state = HashMap::new();
        // Initialize all standard session states with 0
        for state in [
            SessionState::Idle,
            SessionState::Starting,
            SessionState::Working,
            SessionState::WaitingForHuman,
            SessionState::Paused,
            SessionState::RateLimited,
            SessionState::Stopping,
            SessionState::Stopped,
            SessionState::Crashed,
            SessionState::Restarting,
            SessionState::HandedOff,
            SessionState::Failed,
        ] {
            sessions_active_by_state.insert(state.to_string(), 0u64);
        }

        let mut session_durations = Vec::new();
        let mut session_restarts_count = 0u64;
        let mut session_crashes_in_memory = 0u64;

        for s in &sessions {
            *sessions_active_by_state.entry(s.state.to_string()).or_insert(0) += 1;
            session_restarts_count += s.restart_count as u64;
            if s.state == SessionState::Crashed {
                session_crashes_in_memory += 1;
            }

            // Exclude unstarted sessions from duration histogram
            if let Some(start) = s.started_at {
                let duration = if let Some(stop) = s.stopped_at {
                    (stop - start).num_milliseconds() as f64 / 1000.0
                } else {
                    (now - start).num_milliseconds() as f64 / 1000.0
                };
                session_durations.push(duration.max(0.0));
            }
        }

        let session_duration_seconds =
            HistogramSnapshot::new(SESSION_DURATION_BUCKETS, &session_durations);

        // Check event store for historical total events and crashes
        let mut events_max_seq = 0u64;
        let mut historical_crashes = 0u64;
        let mut historical_restarts = 0u64;
        let mut historical_sessions_created = 0u64;

        if let Ok(events) = self.session_mgr.query_events(None, None).await {
            if let Some(last) = events.last() {
                events_max_seq = last.seq;
            }
            for e in &events {
                match e.kind {
                    EventKind::SessionCreated => historical_sessions_created += 1,
                    EventKind::SessionCrashed => historical_crashes += 1,
                    EventKind::SessionRestartAttempted => historical_restarts += 1,
                    _ => {}
                }
            }
        }

        self.state.events_total.fetch_max(events_max_seq, Ordering::Relaxed);
        let events_total = self.state.events_total.load(Ordering::Relaxed);

        let sessions_total = self
            .state
            .sessions_created
            .load(Ordering::Relaxed)
            .max(historical_sessions_created)
            .max(sessions.len() as u64);

        let session_crashes_total = self
            .state
            .session_crashes
            .load(Ordering::Relaxed)
            .max(historical_crashes)
            .max(session_crashes_in_memory);

        let session_restarts_total = self
            .state
            .session_restarts
            .load(Ordering::Relaxed)
            .max(historical_restarts)
            .max(session_restarts_count);

        // 2. Interaction Hub state
        let mut interactions_total_by_decision = HashMap::new();
        for dec in ["allow", "deny", "require_human", "dismissed", "expired"] {
            interactions_total_by_decision.insert(dec.to_owned(), 0u64);
        }

        let mut interactions_pending = 0u64;
        let mut approval_latencies = Vec::new();

        if let Some(hub_handle) = &self.interaction_hub {
            let hub = hub_handle.0.lock().unwrap();
            let all_interactions = hub.list(None, None);

            for i in all_interactions {
                if i.state == InteractionState::Pending {
                    interactions_pending += 1;
                }

                if let Some(dec) = &i.decision {
                    let key = match dec {
                        PolicyDecision::Allow => "allow",
                        PolicyDecision::Deny => "deny",
                        PolicyDecision::RequireHuman => "require_human",
                    };
                    *interactions_total_by_decision.entry(key.to_owned()).or_insert(0) += 1;
                } else if i.state == InteractionState::Dismissed {
                    *interactions_total_by_decision.entry("dismissed".to_owned()).or_insert(0) += 1;
                } else if i.state == InteractionState::Expired {
                    *interactions_total_by_decision.entry("expired".to_owned()).or_insert(0) += 1;
                }

                if let Some(resolved) = i.resolved_at {
                    let latency = (resolved - i.created_at).num_milliseconds() as f64 / 1000.0;
                    approval_latencies.push(latency.max(0.0));
                }
            }
        }

        let approval_latency_seconds =
            HistogramSnapshot::new(APPROVAL_LATENCY_BUCKETS, &approval_latencies);

        // 3. Account Manager state
        let mut accounts_total_by_provider = HashMap::new();
        let mut account_concurrency_caps = Vec::new();

        if let Some(acct_handle) = &self.account_mgr {
            let mgr = acct_handle.0.lock().unwrap();
            let accounts = mgr.list(None, &[]);

            for a in accounts {
                *accounts_total_by_provider.entry(a.provider.clone()).or_insert(0) += 1;
                account_concurrency_caps.push(AccountCapSnapshot {
                    account_id: a.id.0.clone(),
                    label: a.label.clone(),
                    provider: a.provider.clone(),
                    concurrency_cap: a.concurrency_cap,
                    active_sessions: a.active_session_count,
                });
            }
        }

        // Sort account caps deterministically by account_id
        account_concurrency_caps.sort_by(|a, b| a.account_id.cmp(&b.account_id));

        Ok(DaemonMetricsSnapshot {
            timestamp: now.to_rfc3339(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            sessions_total,
            sessions_active_by_state,
            session_crashes_total,
            session_restarts_total,
            session_duration_seconds,
            interactions_total_by_decision,
            interactions_pending,
            approval_latency_seconds,
            accounts_total_by_provider,
            account_concurrency_caps,
            events_total,
        })
    }

    /// Format snapshot into standard Prometheus 0.0.4 text format with proper headers and escaping.
    pub fn format_prometheus(snapshot: &DaemonMetricsSnapshot) -> String {
        let mut out = String::with_capacity(4096);

        // 1. Sessions total
        out.push_str("# HELP agentcontrol_sessions_total Total number of agent sessions created.\n");
        out.push_str("# TYPE agentcontrol_sessions_total counter\n");
        out.push_str(&format!("agentcontrol_sessions_total {}\n\n", snapshot.sessions_total));

        // 2. Sessions active by state
        out.push_str("# HELP agentcontrol_sessions_active Number of agent sessions by state.\n");
        out.push_str("# TYPE agentcontrol_sessions_active gauge\n");
        let mut state_keys: Vec<_> = snapshot.sessions_active_by_state.keys().collect();
        state_keys.sort();
        for state in state_keys {
            let count = snapshot.sessions_active_by_state[state];
            out.push_str(&format!(
                "agentcontrol_sessions_active{{state=\"{}\"}} {}\n",
                escape_label(state),
                count
            ));
        }
        out.push('\n');

        // 3. Session crashes total
        out.push_str("# HELP agentcontrol_session_crashes_total Total session crash events.\n");
        out.push_str("# TYPE agentcontrol_session_crashes_total counter\n");
        out.push_str(&format!(
            "agentcontrol_session_crashes_total {}\n\n",
            snapshot.session_crashes_total
        ));

        // 4. Session restarts total
        out.push_str("# HELP agentcontrol_session_restarts_total Total session restart events.\n");
        out.push_str("# TYPE agentcontrol_session_restarts_total counter\n");
        out.push_str(&format!(
            "agentcontrol_session_restarts_total {}\n\n",
            snapshot.session_restarts_total
        ));

        // 5. Session duration histogram
        out.push_str("# HELP agentcontrol_session_duration_seconds Session duration in seconds.\n");
        out.push_str("# TYPE agentcontrol_session_duration_seconds histogram\n");
        for (le, cumulative) in &snapshot.session_duration_seconds.buckets {
            out.push_str(&format!(
                "agentcontrol_session_duration_seconds_bucket{{le=\"{}\"}} {}\n",
                format_le(*le),
                cumulative
            ));
        }
        out.push_str(&format!(
            "agentcontrol_session_duration_seconds_bucket{{le=\"+Inf\"}} {}\n",
            snapshot.session_duration_seconds.count
        ));
        out.push_str(&format!(
            "agentcontrol_session_duration_seconds_sum {:.4}\n",
            snapshot.session_duration_seconds.sum
        ));
        out.push_str(&format!(
            "agentcontrol_session_duration_seconds_count {}\n\n",
            snapshot.session_duration_seconds.count
        ));

        // 6. Interactions total by decision
        out.push_str("# HELP agentcontrol_interactions_total Total interactions resolved by decision.\n");
        out.push_str("# TYPE agentcontrol_interactions_total counter\n");
        let mut decision_keys: Vec<_> = snapshot.interactions_total_by_decision.keys().collect();
        decision_keys.sort();
        for decision in decision_keys {
            let count = snapshot.interactions_total_by_decision[decision];
            out.push_str(&format!(
                "agentcontrol_interactions_total{{decision=\"{}\"}} {}\n",
                escape_label(decision),
                count
            ));
        }
        out.push('\n');

        // 7. Interactions pending
        out.push_str("# HELP agentcontrol_interactions_pending Number of pending interactions awaiting resolution.\n");
        out.push_str("# TYPE agentcontrol_interactions_pending gauge\n");
        out.push_str(&format!(
            "agentcontrol_interactions_pending {}\n\n",
            snapshot.interactions_pending
        ));

        // 8. Interaction approval latency histogram
        out.push_str("# HELP agentcontrol_interaction_approval_latency_seconds Interaction approval latency in seconds.\n");
        out.push_str("# TYPE agentcontrol_interaction_approval_latency_seconds histogram\n");
        for (le, cumulative) in &snapshot.approval_latency_seconds.buckets {
            out.push_str(&format!(
                "agentcontrol_interaction_approval_latency_seconds_bucket{{le=\"{}\"}} {}\n",
                format_le(*le),
                cumulative
            ));
        }
        out.push_str(&format!(
            "agentcontrol_interaction_approval_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
            snapshot.approval_latency_seconds.count
        ));
        out.push_str(&format!(
            "agentcontrol_interaction_approval_latency_seconds_sum {:.4}\n",
            snapshot.approval_latency_seconds.sum
        ));
        out.push_str(&format!(
            "agentcontrol_interaction_approval_latency_seconds_count {}\n\n",
            snapshot.approval_latency_seconds.count
        ));

        // 9. Accounts total by provider
        out.push_str("# HELP agentcontrol_accounts_total Number of registered accounts by provider.\n");
        out.push_str("# TYPE agentcontrol_accounts_total gauge\n");
        let mut provider_keys: Vec<_> = snapshot.accounts_total_by_provider.keys().collect();
        provider_keys.sort();
        if provider_keys.is_empty() {
            out.push_str("agentcontrol_accounts_total 0\n");
        } else {
            for provider in provider_keys {
                let count = snapshot.accounts_total_by_provider[provider];
                out.push_str(&format!(
                    "agentcontrol_accounts_total{{provider=\"{}\"}} {}\n",
                    escape_label(provider),
                    count
                ));
            }
        }
        out.push('\n');

        // 10. Account concurrency cap
        out.push_str("# HELP agentcontrol_account_concurrency_cap Configured maximum concurrency per account.\n");
        out.push_str("# TYPE agentcontrol_account_concurrency_cap gauge\n");
        for cap in &snapshot.account_concurrency_caps {
            out.push_str(&format!(
                "agentcontrol_account_concurrency_cap{{account_id=\"{}\",label=\"{}\",provider=\"{}\"}} {}\n",
                escape_label(&cap.account_id),
                escape_label(&cap.label),
                escape_label(&cap.provider),
                cap.concurrency_cap
            ));
        }
        out.push('\n');

        // 11. Account active sessions
        out.push_str("# HELP agentcontrol_account_active_sessions Current active sessions executing per account.\n");
        out.push_str("# TYPE agentcontrol_account_active_sessions gauge\n");
        for cap in &snapshot.account_concurrency_caps {
            out.push_str(&format!(
                "agentcontrol_account_active_sessions{{account_id=\"{}\",label=\"{}\",provider=\"{}\"}} {}\n",
                escape_label(&cap.account_id),
                escape_label(&cap.label),
                escape_label(&cap.provider),
                cap.active_sessions
            ));
        }
        out.push('\n');

        // 12. Events total
        out.push_str("# HELP agentcontrol_events_total Total number of events recorded in event store.\n");
        out.push_str("# TYPE agentcontrol_events_total counter\n");
        out.push_str(&format!("agentcontrol_events_total {}\n", snapshot.events_total));

        out
    }

    /// Format snapshot into structured JSON representation.
    pub fn format_json(snapshot: &DaemonMetricsSnapshot) -> serde_json::Value {
        serde_json::json!({
            "timestamp": snapshot.timestamp,
            "version": snapshot.version,
            "sessions": {
                "total": snapshot.sessions_total,
                "active_by_state": snapshot.sessions_active_by_state,
                "crashes_total": snapshot.session_crashes_total,
                "restarts_total": snapshot.session_restarts_total,
                "duration_seconds": {
                    "count": snapshot.session_duration_seconds.count,
                    "sum": snapshot.session_duration_seconds.sum,
                    "buckets": snapshot.session_duration_seconds.buckets.iter().map(|(le, count)| {
                        serde_json::json!({ "le": le, "count": count })
                    }).collect::<Vec<_>>(),
                }
            },
            "interactions": {
                "total_by_decision": snapshot.interactions_total_by_decision,
                "pending": snapshot.interactions_pending,
                "approval_latency_seconds": {
                    "count": snapshot.approval_latency_seconds.count,
                    "sum": snapshot.approval_latency_seconds.sum,
                    "buckets": snapshot.approval_latency_seconds.buckets.iter().map(|(le, count)| {
                        serde_json::json!({ "le": le, "count": count })
                    }).collect::<Vec<_>>(),
                }
            },
            "accounts": {
                "total_by_provider": snapshot.accounts_total_by_provider,
                "caps": snapshot.account_concurrency_caps,
            },
            "events": {
                "total": snapshot.events_total,
            }
        })
    }
}

/// Helper to escape Prometheus label values per the Prometheus 0.0.4 spec:
/// `\` -> `\\`, `"` -> `\"`, `\n` -> `\n`.
fn escape_label(val: &str) -> String {
    val.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn format_le(le: f64) -> String {
    if le.fract() == 0.0 {
        format!("{:.0}", le)
    } else {
        format!("{}", le)
    }
}

// ── Lightweight HTTP Server ──────────────────────────────────────────────────

/// Lightweight embedded HTTP server serving metrics and liveness health checks.
pub struct HttpServer {
    listener: TcpListener,
    collector: MetricsCollector,
}

impl HttpServer {
    /// Bind HTTP listener to the specified address.
    pub async fn bind(addr: &str, collector: MetricsCollector) -> Result<Self, std::io::Error> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, collector })
    }

    /// Return the bound socket address (useful for dynamic port allocation e.g. "127.0.0.1:0").
    pub fn local_addr(&self) -> Result<SocketAddr, std::io::Error> {
        self.listener.local_addr()
    }

    /// Run the server loop accepting HTTP connections.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, _peer_addr)) => {
                    let collector = self.collector.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_http_connection(stream, collector).await {
                            tracing::debug!("HTTP connection error: {e}");
                        }
                    });
                }
                Err(e) => {
                    tracing::debug!("HTTP accept error: {e}");
                    break;
                }
            }
        }
    }
}

async fn handle_http_connection(
    mut stream: TcpStream,
    collector: MetricsCollector,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_str = String::from_utf8_lossy(&buf[..n]);
    let first_line = request_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method != "GET" && method != "HEAD" {
        let resp = "HTTP/1.1 405 Method Not Allowed\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 18\r\nConnection: close\r\n\r\nMethod Not Allowed";
        stream.write_all(resp.as_bytes()).await?;
        stream.flush().await?;
        return Ok(());
    }

    let clean_path = path.split('?').next().unwrap_or(path).trim_end_matches('/');
    let clean_path = if clean_path.is_empty() { "/" } else { clean_path };

    match clean_path {
        "/metrics" => {
            let body = match collector.gather().await {
                Ok(snapshot) => MetricsCollector::format_prometheus(&snapshot),
                Err(e) => format!("# Error gathering metrics: {e}\n"),
            };
            let body_bytes = body.as_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            );
            stream.write_all(header.as_bytes()).await?;
            if method == "GET" {
                stream.write_all(body_bytes).await?;
            }
            stream.flush().await?;
        }
        "/health" | "/livez" => {
            let body = serde_json::json!({
                "status": "ok",
                "version": env!("CARGO_PKG_VERSION"),
            })
            .to_string();
            let body_bytes = body.as_bytes();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body_bytes.len()
            );
            stream.write_all(header.as_bytes()).await?;
            if method == "GET" {
                stream.write_all(body_bytes).await?;
            }
            stream.flush().await?;
        }
        _ => {
            let body = "Not Found";
            let header = format!(
                "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(header.as_bytes()).await?;
            stream.flush().await?;
        }
    }

    Ok(())
}
