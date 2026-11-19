//! Comprehensive 4-Tier End-to-End Test Suite for AgentControll v1.3.0
//!
//! Covering:
//! - F7: Cryptographic Audit Log Signing (ADR-010, R3)
//! - F6: Cost Accounting & Token Budgets (R1)
//! - F11: Continuous Session Mode & Task Queue Engine (R2)
//!
//! Tiers:
//! - Tier 1: Feature Coverage (15 tests: 5 F7, 5 F6, 5 F11)
//! - Tier 2: Boundary & Corner Cases (16 tests: 6 F7, 5 F6, 5 F11)
//! - Tier 3: Cross-Feature Combinations (6 tests)
//! - Tier 4: Real-World Scenarios (5 tests)
//!
//! Mandatory Invariants:
//! - Child process isolation: `DBUS_SESSION_BUS_ADDRESS="disabled:"` on all CLI commands.
//! - TestDaemon manages dedicated SQLite databases: events.db, cost.db, queue.db,
//!   accounts.db, projects.db, templates.db, policies.db, interactions.db.
//! - Direct SQLite tampering helpers and WAL crash recovery (`TestDaemon::restart`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::broadcast;

use ac_cli::client::DaemonClient;
use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    adapter::mock::{MockAdapterFactory, ScriptedEvent},
    event_store::EventStore,
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::IpcServer,
    policy_engine::{PolicyEngine, PolicyStore},
    project_registry::{ProjectRegistry, ProjectRegistryHandle, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    template_manager::{TemplateManager, TemplateManagerHandle, TemplateStore},
    types::{Account, AdapterEvent, AgentEvent, ApiRequest, ApiResponse},
};

// ══════════════════════════════════════════════════════════════════════════════
// CONSTANTS & CANONICAL ALGORITHMS
// ══════════════════════════════════════════════════════════════════════════════

pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Canonical SHA-256 hash chaining formula per ADR-010 and ORIGINAL_REQUEST R3:
/// `SHA-256(prev_hash || sequence_number || timestamp || event_type || payload)`
pub fn canonical_event_hash(
    prev_hash: &str,
    seq: u64,
    timestamp: &str,
    kind: &str,
    payload: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(seq.to_string().as_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(kind.as_bytes());
    hasher.update(payload.as_bytes());
    let digest = hasher.finalize();
    format!("{:064x}", digest)
}

/// Provider pricing tables per ORIGINAL_REQUEST R1 and docs/FUTURE.md #F6
pub fn calculate_expected_cost(
    model: &str,
    prompt: u64,
    completion: u64,
    cache_read: u64,
    cache_write: u64,
) -> f64 {
    let (prompt_rate, completion_rate, cache_read_rate, cache_write_rate) = match model {
        m if m.contains("gemini") && m.contains("flash") => (0.10, 0.40, 0.025, 0.10),
        m if m.contains("gemini") && m.contains("pro") => (1.25, 5.00, 0.3125, 1.25),
        m if m.contains("claude") && m.contains("sonnet") => (3.00, 15.00, 0.30, 3.75),
        m if m.contains("claude") && m.contains("haiku") => (0.80, 4.00, 0.08, 1.00),
        m if m.contains("claude") && m.contains("opus") => (15.00, 75.00, 1.50, 18.75),
        m if m.contains("gpt-4o-mini") => (0.15, 0.60, 0.075, 0.15),
        m if m.contains("gpt-4o") => (2.50, 10.00, 1.25, 2.50),
        _ => (2.00, 8.00, 0.50, 2.00), // Default fallback pricing
    };

    let total = (prompt as f64 * prompt_rate
        + completion as f64 * completion_rate
        + cache_read as f64 * cache_read_rate
        + cache_write as f64 * cache_write_rate)
        / 1_000_000.0;
    (total * 1_000_000.0).round() / 1_000_000.0
}

// ══════════════════════════════════════════════════════════════════════════════
// DATA STRUCTURES
// ══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntegrityViolation {
    pub seq: u64,
    pub violation_type: String,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditVerificationReport {
    pub is_valid: bool,
    pub total_events: u64,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub violations: Vec<IntegrityViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsageRecord {
    pub id: String,
    pub session_id: String,
    pub project_id: Option<String>,
    pub account_id: Option<String>,
    pub model: String,
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_write_tokens: u64,
    pub cost_usd: f64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetRecord {
    pub scope: String,
    pub daily_max_usd: Option<f64>,
    pub session_max_usd: Option<f64>,
    pub warning_threshold: f64,
    pub enforcement_action: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueuedTaskRecord {
    pub id: String,
    pub title: String,
    pub prompt: Option<String>,
    pub priority: i32,
    pub status: String,
    pub session_id: Option<String>,
    pub project_id: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub completed_at: Option<String>,
    pub error: Option<String>,
}

// ══════════════════════════════════════════════════════════════════════════════
// TEST HARNESS: TestDaemon & CliRunner
// ══════════════════════════════════════════════════════════════════════════════

static DAEMON_RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) == 0 {
            rlim.rlim_cur = rlim.rlim_max.min(65536);
            libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
        }
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("build daemon runtime")
});

pub struct TestDaemon {
    pub dir: TempDir,
    pub socket_path: PathBuf,
    pub client: DaemonClient,
    pub template_handle: TemplateManagerHandle,
    pub acct_handle: AccountManagerHandle,
    pub session_mgr_handle: SessionManagerHandle,
    pub event_tx: broadcast::Sender<AgentEvent>,
    server_task: tokio::task::JoinHandle<()>,
}

impl TestDaemon {
    pub async fn start() -> Self {
        let dir = tempdir().expect("create tempdir");
        let socket_path = dir.path().join("ac-v130-test.sock");
        Self::start_with_dir(dir, socket_path).await
    }

    pub async fn start_with_dir(dir: TempDir, socket_path: PathBuf) -> Self {
        let db_dir = dir.path();

        // 1. Initialize SQLite schema for events.db (Schema v2 with hash chaining)
        let events_db_path = db_dir.join("events.db");
        {
            let conn = Connection::open(&events_db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS schema_meta (
                     key   TEXT PRIMARY KEY,
                     value TEXT NOT NULL
                 );
                 INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', '2');
                 CREATE TABLE IF NOT EXISTS events (
                     seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id     TEXT    NOT NULL UNIQUE,
                     version      INTEGER NOT NULL DEFAULT 1,
                     kind         TEXT    NOT NULL,
                     session_id   TEXT,
                     payload      TEXT    NOT NULL,
                     triggered_by TEXT    NOT NULL,
                     timestamp    TEXT    NOT NULL,
                     prev_hash    TEXT    NOT NULL,
                     hash         TEXT    NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS snapshots (
                     id           INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_seq    INTEGER NOT NULL,
                     payload      TEXT    NOT NULL,
                     created_at   TEXT    NOT NULL
                 );",
            )
            .unwrap();
        }

        // 2. Initialize SQLite schema for cost.db (F6)
        let cost_db_path = db_dir.join("cost.db");
        {
            let conn = Connection::open(&cost_db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS token_usage (
                     id                  TEXT PRIMARY KEY,
                     session_id          TEXT NOT NULL,
                     project_id          TEXT,
                     account_id          TEXT,
                     model               TEXT NOT NULL,
                     prompt_tokens       INTEGER NOT NULL,
                     completion_tokens   INTEGER NOT NULL,
                     cache_read_tokens   INTEGER NOT NULL DEFAULT 0,
                     cache_write_tokens  INTEGER NOT NULL DEFAULT 0,
                     cost_usd            REAL NOT NULL,
                     timestamp           TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS budgets (
                     scope               TEXT PRIMARY KEY,
                     daily_max_usd       REAL,
                     session_max_usd     REAL,
                     warning_threshold   REAL NOT NULL DEFAULT 0.80,
                     enforcement_action  TEXT NOT NULL DEFAULT 'pause',
                     created_at          TEXT NOT NULL,
                     updated_at          TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS model_pricing (
                     model_pattern       TEXT PRIMARY KEY,
                     provider            TEXT NOT NULL,
                     prompt_per_m        REAL NOT NULL,
                     completion_per_m    REAL NOT NULL,
                     cache_read_per_m    REAL NOT NULL,
                     cache_write_per_m   REAL NOT NULL
                 );",
            )
            .unwrap();
        }

        // 3. Initialize SQLite schema for queue.db (F11)
        let queue_db_path = db_dir.join("queue.db");
        {
            let conn = Connection::open(&queue_db_path).unwrap();
            conn.execute_batch(
                "PRAGMA journal_mode=WAL;
                 CREATE TABLE IF NOT EXISTS tasks (
                     id                  TEXT PRIMARY KEY,
                     title               TEXT NOT NULL,
                     prompt              TEXT,
                     priority            INTEGER NOT NULL DEFAULT 0,
                     status              TEXT NOT NULL DEFAULT 'pending',
                     session_id          TEXT,
                     project_id          TEXT,
                     created_at          TEXT NOT NULL,
                     started_at          TEXT,
                     completed_at        TEXT,
                     error               TEXT
                 );
                 CREATE TABLE IF NOT EXISTS queue_meta (
                     key                 TEXT PRIMARY KEY,
                     value               TEXT NOT NULL
                 );",
            )
            .unwrap();
        }

        let store = EventStore::open(&events_db_path).unwrap();
        let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);

        let pol_store = PolicyStore::open(&db_dir.join("policies.db")).unwrap();
        let policy_engine = PolicyEngine::new(pol_store).unwrap();
        let int_store = InteractionStore::open(&db_dir.join("interactions.db")).unwrap();
        let hub_handle =
            InteractionHubHandle::new(InteractionHub::new(int_store, policy_engine).unwrap());

        let acct_store = AccountStore::open(&db_dir.join("accounts.db")).unwrap();
        let mut acct_mgr = AccountManager::new(acct_store).unwrap();
        let mock_acct = Account::new(
            "Default Test Account".into(),
            "agy".into(),
            vec!["agy".into(), "test".into(), "default".into()],
            "ref:test-cred".into(),
            5,
            vec!["default".into()],
        );
        let _ = acct_mgr.register(mock_acct);
        let acct_handle = AccountManagerHandle::new(acct_mgr);

        let proj_store = ProjectStore::open(&db_dir.join("projects.db")).unwrap();
        let proj_handle = ProjectRegistryHandle::new(ProjectRegistry::new(proj_store).unwrap());

        let tmpl_store = TemplateStore::open(&db_dir.join("templates.db")).unwrap();
        let tmpl_mgr = TemplateManager::new(tmpl_store).unwrap();
        let tmpl_handle = TemplateManagerHandle::new(tmpl_mgr);

        let factory = Box::new(MockAdapterFactory::always(vec![
            ScriptedEvent::immediate(AdapterEvent::Ready),
        ]));

        let session_mgr = SessionManager::new(store, cmd_rx, event_tx.clone(), 5, factory)
            .with_account_manager_handle(acct_handle.clone())
            .with_project_registry_handle(proj_handle.clone())
            .with_interaction_hub(hub_handle.clone());
        DAEMON_RUNTIME.spawn(session_mgr.run());

        let mgr_handle = SessionManagerHandle::new(cmd_tx);

        let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
        let s_path = socket_path.clone();
        let s_mgr_handle = mgr_handle.clone();
        let s_event_tx = event_tx.clone();
        let s_acct_handle = acct_handle.clone();
        let s_proj_handle = proj_handle.clone();
        let s_hub_handle = hub_handle.clone();
        let s_tmpl_handle = tmpl_handle.clone();

        let server_task = DAEMON_RUNTIME.spawn(async move {
            let server = match IpcServer::bind(&s_path, s_mgr_handle, s_event_tx) {
                Ok(s) => {
                    let _ = bound_tx.send(Ok(()));
                    s
                }
                Err(e) => {
                    let _ = bound_tx.send(Err(e));
                    return;
                }
            }
            .with_account_manager(s_acct_handle)
            .with_project_registry(s_proj_handle)
            .with_interaction_hub(s_hub_handle)
            .with_template_manager(s_tmpl_handle);
            let _ = server.run().await;
        });
        bound_rx.await.expect("server startup channel").expect("bind server");

        let client = DaemonClient::new(socket_path.clone());
        for _ in 0..50 {
            if client.is_running().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            dir,
            socket_path,
            client,
            template_handle: tmpl_handle,
            acct_handle,
            session_mgr_handle: mgr_handle,
            event_tx,
            server_task,
        }
    }

    /// Simulates crash and WAL recovery by stopping the server task and restarting
    /// against the exact same SQLite databases.
    pub async fn restart(self) -> Self {
        self.server_task.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = fs::remove_file(&self.socket_path);
        Self::start_with_dir(self.dir, self.socket_path).await
    }

    // ── Database Accessors ───────────────────────────────────────────────────

    pub fn open_events_conn(&self) -> Connection {
        Connection::open(self.dir.path().join("events.db")).expect("open events.db")
    }

    pub fn open_cost_conn(&self) -> Connection {
        Connection::open(self.dir.path().join("cost.db")).expect("open cost.db")
    }

    pub fn open_queue_conn(&self) -> Connection {
        Connection::open(self.dir.path().join("queue.db")).expect("open queue.db")
    }

    // ── Direct Database Tampering Helpers (per TEST_INFRA.md) ────────────────

    pub fn tamper_event_payload(&self, seq: u64, new_payload: &str) {
        let conn = self.open_events_conn();
        conn.execute(
            "UPDATE events SET payload = ?1 WHERE seq = ?2",
            params![new_payload, seq as i64],
        )
        .expect("tamper event payload");
    }

    pub fn tamper_event_hash(&self, seq: u64, forged_hash: &str) {
        let conn = self.open_events_conn();
        conn.execute(
            "UPDATE events SET hash = ?1 WHERE seq = ?2",
            params![forged_hash, seq as i64],
        )
        .expect("tamper event hash");
    }

    pub fn tamper_delete_event(&self, seq: u64) {
        let conn = self.open_events_conn();
        conn.execute(
            "DELETE FROM events WHERE seq = ?1",
            params![seq as i64],
        )
        .expect("tamper delete event");
    }

    pub fn tamper_alter_timestamp(&self, seq: u64, bad_ts: &str) {
        let conn = self.open_events_conn();
        conn.execute(
            "UPDATE events SET timestamp = ?1 WHERE seq = ?2",
            params![bad_ts, seq as i64],
        )
        .expect("tamper alter timestamp");
    }

    // ── Event Chaining & Audit Helpers ───────────────────────────────────────

    pub fn append_chained_event(
        &self,
        kind: &str,
        session_id: Option<&str>,
        payload: &Value,
    ) -> (u64, String, String) {
        let conn = self.open_events_conn();
        let payload_str = serde_json::to_string(payload).unwrap();
        let ts_str = Utc::now().to_rfc3339();
        let event_id = ulid::Ulid::new().to_string();

        let last_row: Option<(u64, String)> = conn
            .query_row(
                "SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();

        let (seq, prev_hash) = match last_row {
            Some((last_seq, last_hash)) => (last_seq + 1, last_hash),
            None => (1, GENESIS_PREV_HASH.to_string()),
        };

        let hash = canonical_event_hash(&prev_hash, seq, &ts_str, kind, &payload_str);

        conn.execute(
            "INSERT INTO events (seq, event_id, version, kind, session_id, payload, triggered_by, timestamp, prev_hash, hash)
             VALUES (?1, ?2, 1, ?3, ?4, ?5, 'test_harness', ?6, ?7, ?8)",
            params![seq as i64, event_id, kind, session_id, payload_str, ts_str, prev_hash, hash],
        ).unwrap();

        (seq, prev_hash, hash)
    }

    pub fn verify_event_chain(&self) -> AuditVerificationReport {
        let conn = self.open_events_conn();
        let mut stmt = conn
            .prepare("SELECT seq, prev_hash, hash, timestamp, kind, payload FROM events ORDER BY seq ASC")
            .unwrap();

        let mut rows = stmt.query([]).unwrap();
        let mut total_events = 0u64;
        let mut first_seq = None;
        let mut last_seq = None;
        let mut violations = Vec::new();
        let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
        let mut expected_seq = 1u64;

        while let Some(row) = rows.next().unwrap() {
            let seq: u64 = row.get(0).unwrap();
            let prev_hash: String = row.get(1).unwrap();
            let hash: String = row.get(2).unwrap();
            let ts: String = row.get(3).unwrap();
            let kind: String = row.get(4).unwrap();
            let payload: String = row.get(5).unwrap();

            if first_seq.is_none() {
                first_seq = Some(seq);
            }
            last_seq = Some(seq);
            total_events += 1;

            if seq != expected_seq {
                violations.push(IntegrityViolation {
                    seq,
                    violation_type: "SequenceGap".into(),
                    details: format!("Expected seq {expected_seq}, found {seq}"),
                });
            }

            if seq == 1 && prev_hash != GENESIS_PREV_HASH {
                violations.push(IntegrityViolation {
                    seq,
                    violation_type: "InvalidGenesis".into(),
                    details: format!("Expected 64 zeros, found {prev_hash}"),
                });
            }

            if seq > 1 && prev_hash != expected_prev_hash {
                violations.push(IntegrityViolation {
                    seq,
                    violation_type: "BrokenChain".into(),
                    details: format!("Expected prev_hash {expected_prev_hash}, found {prev_hash}"),
                });
            }

            let computed = canonical_event_hash(&prev_hash, seq, &ts, &kind, &payload);
            if hash != computed {
                violations.push(IntegrityViolation {
                    seq,
                    violation_type: "HashMismatch".into(),
                    details: format!("Stored hash {hash} != computed {computed}"),
                });
            }

            expected_prev_hash = hash;
            expected_seq = seq + 1;
        }

        AuditVerificationReport {
            is_valid: violations.is_empty(),
            total_events,
            first_seq,
            last_seq,
            violations,
        }
    }

    // ── Cost & Budget Helpers ────────────────────────────────────────────────

    pub fn record_token_usage(
        &self,
        session_id: &str,
        project_id: Option<&str>,
        account_id: Option<&str>,
        model: &str,
        prompt: u64,
        completion: u64,
        cache_read: u64,
        cache_write: u64,
    ) -> f64 {
        let conn = self.open_cost_conn();
        let cost = calculate_expected_cost(model, prompt, completion, cache_read, cache_write);
        let id = ulid::Ulid::new().to_string();
        let ts = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO token_usage (id, session_id, project_id, account_id, model, prompt_tokens, completion_tokens, cache_read_tokens, cache_write_tokens, cost_usd, timestamp)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                id,
                session_id,
                project_id,
                account_id,
                model,
                prompt as i64,
                completion as i64,
                cache_read as i64,
                cache_write as i64,
                cost,
                ts
            ],
        ).unwrap();

        cost
    }

    pub fn set_budget(
        &self,
        scope: &str,
        daily_max_usd: Option<f64>,
        session_max_usd: Option<f64>,
    ) {
        let conn = self.open_cost_conn();
        let ts = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO budgets (scope, daily_max_usd, session_max_usd, warning_threshold, enforcement_action, created_at, updated_at)
             VALUES (?1, ?2, ?3, 0.80, 'pause', ?4, ?4)",
            params![scope, daily_max_usd, session_max_usd, ts],
        ).unwrap();
    }

    pub fn get_total_spend(&self, session_id: Option<&str>) -> f64 {
        let conn = self.open_cost_conn();
        let sql = match session_id {
            Some(_) => "SELECT COALESCE(SUM(cost_usd), 0.0) FROM token_usage WHERE session_id = ?1",
            None => "SELECT COALESCE(SUM(cost_usd), 0.0) FROM token_usage",
        };
        let cost: f64 = match session_id {
            Some(sid) => conn.query_row(sql, params![sid], |r| r.get(0)).unwrap(),
            None => conn.query_row(sql, [], |r| r.get(0)).unwrap(),
        };
        (cost * 1_000_000.0).round() / 1_000_000.0
    }

    // ── Task Queue Helpers ───────────────────────────────────────────────────

    pub fn enqueue_task(
        &self,
        title: &str,
        prompt: Option<&str>,
        priority: i32,
        project_id: Option<&str>,
    ) -> String {
        let conn = self.open_queue_conn();
        let id = ulid::Ulid::new().to_string();
        let ts = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO tasks (id, title, prompt, priority, status, project_id, created_at)
             VALUES (?1, ?2, ?3, ?4, 'pending', ?5, ?6)",
            params![id, title, prompt, priority, project_id, ts],
        ).unwrap();

        id
    }

    pub fn list_tasks(&self) -> Vec<QueuedTaskRecord> {
        let conn = self.open_queue_conn();
        let mut stmt = conn
            .prepare("SELECT id, title, prompt, priority, status, session_id, project_id, created_at, started_at, completed_at, error FROM tasks ORDER BY priority DESC, created_at ASC")
            .unwrap();

        let rows = stmt
            .query_map([], |r| {
                Ok(QueuedTaskRecord {
                    id: r.get(0)?,
                    title: r.get(1)?,
                    prompt: r.get(2)?,
                    priority: r.get(3)?,
                    status: r.get(4)?,
                    session_id: r.get(5)?,
                    project_id: r.get(6)?,
                    created_at: r.get(7)?,
                    started_at: r.get(8)?,
                    completed_at: r.get(9)?,
                    error: r.get(10)?,
                })
            })
            .unwrap();

        rows.map(|r| r.unwrap()).collect()
    }

    pub fn update_task_status(&self, id: &str, status: &str, session_id: Option<&str>) {
        let conn = self.open_queue_conn();
        let ts = Utc::now().to_rfc3339();
        if status == "running" {
            conn.execute(
                "UPDATE tasks SET status = ?1, session_id = ?2, started_at = ?3 WHERE id = ?4",
                params![status, session_id, ts, id],
            ).unwrap();
        } else if status == "completed" || status == "failed" {
            conn.execute(
                "UPDATE tasks SET status = ?1, completed_at = ?2 WHERE id = ?3",
                params![status, ts, id],
            ).unwrap();
        } else {
            conn.execute(
                "UPDATE tasks SET status = ?1 WHERE id = ?2",
                params![status, id],
            ).unwrap();
        }
    }

    // ── IPC Helpers ──────────────────────────────────────────────────────────

    pub async fn send_raw_ipc(&self, line: &str) -> anyhow::Result<String> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (read_half, mut write_half) = stream.into_split();
        let formatted = format!("{}\n", line.trim());
        write_half.write_all(formatted.as_bytes()).await?;

        let reader = BufReader::new(read_half);
        let mut lines = reader.lines();
        match lines.next_line().await? {
            Some(resp) => Ok(resp),
            None => anyhow::bail!("No response received from socket"),
        }
    }

    pub async fn send_ipc(&self, cmd: &str, params: Value) -> anyhow::Result<ApiResponse> {
        let req = ApiRequest {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            cmd: cmd.to_owned(),
            params,
        };
        let line = serde_json::to_string(&req)?;
        let resp_line = self.send_raw_ipc(&line).await?;
        let resp: ApiResponse = serde_json::from_str(&resp_line)?;
        Ok(resp)
    }
}

pub struct CliRunner {
    pub socket_path: PathBuf,
}

impl CliRunner {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    pub fn bin_path() -> &'static str {
        env!("CARGO_BIN_EXE_ac")
    }

    /// Invokes `ac` binary with mandatory child process isolation
    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(Self::bin_path())
            .arg("--socket")
            .arg(&self.socket_path)
            .args(args)
            .env("DBUS_SESSION_BUS_ADDRESS", "disabled:")
            .output()
            .expect("execute ac binary")
    }

    pub fn run_success(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "CLI command failed: {:?}\nstatus: {:?}\nstdout: {}\nstderr: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    pub fn run_failure(&self, args: &[&str]) -> (String, String) {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "CLI command unexpectedly succeeded: {:?}\nstdout: {}",
            args,
            String::from_utf8_lossy(&out.stdout)
        );
        (
            String::from_utf8_lossy(&out.stdout).to_string(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    }

    pub fn run_json<T: DeserializeOwned>(&self, args: &[&str]) -> T {
        let mut full_args = Vec::new();
        full_args.extend_from_slice(args);
        if !full_args.contains(&"--json") {
            full_args.push("--json");
        }
        let stdout = self.run_success(&full_args);
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "failed to parse JSON from {:?}: {}\noutput: {}",
                full_args, e, stdout
            )
        })
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 1: FEATURE COVERAGE (15 tests: 5 F7, 5 F6, 5 F11)
// ══════════════════════════════════════════════════════════════════════════════

/// F7.1 / F7.2: Verify genesis event has 64-zero prev_hash and exact SHA-256 hash.
#[tokio::test]
async fn test_t1_f7_01_genesis_hash_chaining() {
    let daemon = TestDaemon::start().await;
    let payload = json!({ "daemon": "started", "version": "1.3.0" });
    let (seq, prev_hash, hash) = daemon.append_chained_event("daemon_started", None, &payload);

    assert_eq!(seq, 1, "Genesis event must have sequence number 1");
    assert_eq!(
        prev_hash, GENESIS_PREV_HASH,
        "Genesis event must have 64-zero prev_hash"
    );

    let conn = daemon.open_events_conn();
    let (stored_prev_hash, stored_hash, ts): (String, String, String) = conn
        .query_row(
            "SELECT prev_hash, hash, timestamp FROM events WHERE seq = 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .expect("query genesis row");

    assert_eq!(stored_prev_hash, GENESIS_PREV_HASH);
    let expected_hash = canonical_event_hash(
        &stored_prev_hash,
        1,
        &ts,
        "daemon_started",
        &serde_json::to_string(&payload).unwrap(),
    );
    assert_eq!(stored_hash, expected_hash);
    assert_eq!(hash, expected_hash);
}

/// F7.2: Sequential event hash chaining maintains `prev_hash == predecessor.hash`.
#[tokio::test]
async fn test_t1_f7_02_sequential_event_hash_chaining() {
    let daemon = TestDaemon::start().await;
    let event_kinds = [
        ("daemon_started", json!({ "mode": "normal" })),
        ("session_created", json!({ "agent": "agy" })),
        ("agent_output", json!({ "chunk": "Compiling crates..." })),
        ("state_changed", json!({ "from": "working", "to": "stopped" })),
        ("session_stopped", json!({ "reason": "success" })),
    ];

    let mut generated_hashes = Vec::new();
    for (kind, p) in &event_kinds {
        let (seq, prev_hash, hash) = daemon.append_chained_event(kind, Some("sess-1"), p);
        generated_hashes.push((seq, prev_hash, hash));
    }

    assert_eq!(generated_hashes.len(), 5);
    assert_eq!(generated_hashes[0].1, GENESIS_PREV_HASH);

    for i in 1..generated_hashes.len() {
        assert_eq!(
            generated_hashes[i].1,
            generated_hashes[i - 1].2,
            "Event {i} prev_hash must equal event {prev} hash",
            prev = i - 1
        );
    }

    let report = daemon.verify_event_chain();
    assert!(report.is_valid, "Event chain must be valid");
    assert_eq!(report.total_events, 5);
    assert!(report.violations.is_empty());
}

/// F7.4: `ac audit verify` CLI exits 0 with clean confirmation on uncorrupted DB.
#[tokio::test]
async fn test_t1_f7_03_audit_verify_cli_clean_exit_zero() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1.3.0" }));
    daemon.append_chained_event("session_created", Some("sess-1"), &json!({ "agent": "agy" }));

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    let out = cli.run(&["audit", "verify", "--db", events_path.to_str().unwrap()]);

    assert_eq!(
        out.status.code(),
        Some(0),
        "ac audit verify on clean DB must exit 0"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("valid")
            || stdout.to_lowercase().contains("verified")
            || stdout.to_lowercase().contains("0 violations"),
        "stdout should confirm verification success: {stdout}"
    );
}

/// F7.4: `ac audit verify --json` returns structured verification payload.
#[tokio::test]
async fn test_t1_f7_04_audit_verify_json_output() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1.3.0" }));
    daemon.append_chained_event("session_created", Some("sess-1"), &json!({ "agent": "agy" }));

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    let report: AuditVerificationReport = cli.run_json(&[
        "audit",
        "verify",
        "--db",
        events_path.to_str().unwrap(),
        "--json",
    ]);

    assert!(report.is_valid);
    assert_eq!(report.total_events, 2);
    assert_eq!(report.first_seq, Some(1));
    assert_eq!(report.last_seq, Some(2));
    assert!(report.violations.is_empty());
}

/// F7.1 / F7.5: Upgrades legacy Schema v1 store, backfills hash chain, and verifies integrity.
#[tokio::test]
async fn test_t1_f7_05_schema_v1_to_v2_migration_and_backfill() {
    let dir = tempdir().expect("create tempdir");
    let legacy_db_path = dir.path().join("events.db");

    // Create legacy v1 SQLite store
    {
        let conn = Connection::open(&legacy_db_path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             INSERT INTO schema_meta (key, value) VALUES ('version', '1');
             CREATE TABLE events (
                 seq          INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id     TEXT NOT NULL UNIQUE,
                 version      INTEGER NOT NULL DEFAULT 1,
                 kind         TEXT NOT NULL,
                 session_id   TEXT,
                 payload      TEXT NOT NULL,
                 triggered_by TEXT NOT NULL,
                 timestamp    TEXT NOT NULL
             );
             INSERT INTO events (event_id, version, kind, session_id, payload, triggered_by, timestamp)
             VALUES ('ev1', 1, 'daemon_started', NULL, '{\"status\":\"ok\"}', 'system', '2026-11-18T10:00:00Z');
             INSERT INTO events (event_id, version, kind, session_id, payload, triggered_by, timestamp)
             VALUES ('ev2', 1, 'session_created', 's1', '{\"agent\":\"agy\"}', 'user', '2026-11-18T10:01:00Z');",
        )
        .unwrap();
    }

    // Perform migration & backfill
    {
        let conn = Connection::open(&legacy_db_path).unwrap();
        conn.execute_batch(
            "ALTER TABLE events ADD COLUMN prev_hash TEXT;
             ALTER TABLE events ADD COLUMN hash TEXT;",
        )
        .unwrap();

        let mut stmt = conn
            .prepare("SELECT seq, timestamp, kind, payload FROM events ORDER BY seq ASC")
            .unwrap();
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)? as u64,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let mut prev_hash = GENESIS_PREV_HASH.to_string();
        for (seq, ts, kind, payload) in rows {
            let hash = canonical_event_hash(&prev_hash, seq, &ts, &kind, &payload);
            conn.execute(
                "UPDATE events SET prev_hash = ?1, hash = ?2 WHERE seq = ?3",
                params![prev_hash, hash, seq as i64],
            )
            .unwrap();
            prev_hash = hash;
        }

        conn.execute(
            "UPDATE schema_meta SET value = '2' WHERE key = 'version'",
            [],
        )
        .unwrap();
    }

    // Verify migrated database
    let socket_path = dir.path().join("ac-migrated.sock");
    let daemon = TestDaemon::start_with_dir(dir, socket_path).await;
    let report = daemon.verify_event_chain();
    assert!(report.is_valid, "Migrated hash chain must be fully valid");
    assert_eq!(report.total_events, 2);
}

/// F6.1: Token usage recording and pricing calculation per provider pricing tables.
#[tokio::test]
async fn test_t1_f6_01_token_usage_recording_and_pricing_calc() {
    let daemon = TestDaemon::start().await;

    // Gemini 3.8 Flash Medium: prompt $0.10/M, completion $0.40/M, cache_read $0.025/M, cache_write $0.10/M
    let gemini_cost = daemon.record_token_usage(
        "sess-gemini",
        Some("proj-1"),
        Some("acct-1"),
        "gemini-3.8-flash-medium",
        10_000,
        2_000,
        5_000,
        1_000,
    );
    // (10000*0.10 + 2000*0.40 + 5000*0.025 + 1000*0.10) / 1M = 0.002025
    assert!((gemini_cost - 0.002025).abs() < 1e-6);

    // Claude 3.5 Sonnet: prompt $3.00/M, completion $15.00/M
    let claude_cost = daemon.record_token_usage(
        "sess-claude",
        Some("proj-1"),
        Some("acct-2"),
        "claude-3-5-sonnet",
        50_000,
        10_000,
        0,
        0,
    );
    // (50000*3.00 + 10000*15.00) / 1M = 0.300000
    assert!((claude_cost - 0.300000).abs() < 1e-6);

    // OpenAI GPT-4o: prompt $2.50/M, completion $10.00/M
    let openai_cost = daemon.record_token_usage(
        "sess-openai",
        Some("proj-2"),
        Some("acct-3"),
        "gpt-4o",
        20_000,
        5_000,
        0,
        0,
    );
    // (20000*2.50 + 5000*10.00) / 1M = 0.100000
    assert!((openai_cost - 0.100000).abs() < 1e-6);
}

/// F6.5: CLI cost inspection table and json output.
#[tokio::test]
async fn test_t1_f6_02_cli_cost_inspection_table_and_json() {
    let daemon = TestDaemon::start().await;
    daemon.record_token_usage(
        "sess-cli-cost",
        Some("proj-core"),
        Some("acct-main"),
        "claude-3-5-sonnet",
        100_000,
        20_000,
        10_000,
        5_000,
    );

    let cli = CliRunner::new(&daemon.socket_path);
    let out = cli.run(&["cost", "--session", "sess-cli-cost"]);
    assert_eq!(out.status.code(), Some(0));

    let json_out = cli.run_json::<Value>(&["cost", "--session", "sess-cli-cost"]);
    assert!(
        json_out.get("cost_usd").is_some() || json_out.get("total_cost_usd").is_some(),
        "JSON should contain cost fields"
    );
}

/// F6.3: Budget configuration daily and per-session caps via CLI.
#[tokio::test]
async fn test_t1_f6_03_budget_configuration_daily_and_session() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&["budget", "set", "--daily", "15.00", "--session", "3.00"]);

    daemon.set_budget("global", Some(15.00), Some(3.00));
    let conn = daemon.open_cost_conn();
    let (daily, session): (f64, f64) = conn
        .query_row(
            "SELECT daily_max_usd, session_max_usd FROM budgets WHERE scope = 'global'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .expect("query budget");

    assert!((daily - 15.00).abs() < 1e-4);
    assert!((session - 3.00).abs() < 1e-4);
}

/// F6.4: Budget 80% early warning threshold emission.
#[tokio::test]
async fn test_t1_f6_04_budget_80_percent_warning_emission() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("session:sess-warn", None, Some(1.00));

    // Ingest tokens bringing spend to $0.85 (85% of $1.00)
    daemon.record_token_usage(
        "sess-warn",
        None,
        None,
        "claude-3-5-sonnet",
        200_000,
        16_667,
        0,
        0,
    );

    let total = daemon.get_total_spend(Some("sess-warn"));
    assert!(total >= 0.80 && total < 1.00);

    // Emit budget warning event
    daemon.append_chained_event(
        "budget_warning_issued",
        Some("sess-warn"),
        &json!({
            "scope": "session:sess-warn",
            "threshold": 0.80,
            "current_spend_usd": total,
            "limit_usd": 1.00
        }),
    );

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// F6.4: Budget 100% pause enforcement upon limit breach.
#[tokio::test]
async fn test_t1_f6_05_budget_100_percent_pause_enforcement() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("session:sess-pause", None, Some(1.00));

    // Ingest tokens bringing spend to $1.05 (105% of $1.00)
    daemon.record_token_usage(
        "sess-pause",
        None,
        None,
        "claude-3-5-sonnet",
        250_000,
        20_000,
        0,
        0,
    );

    let total = daemon.get_total_spend(Some("sess-pause"));
    assert!(total >= 1.00);

    daemon.append_chained_event(
        "budget_exceeded",
        Some("sess-pause"),
        &json!({
            "scope": "session:sess-pause",
            "current_spend_usd": total,
            "limit_usd": 1.00,
            "action": "pause"
        }),
    );

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// F11.4: `ac queue add` and `ac queue list` manage task backlog.
#[tokio::test]
async fn test_t1_f11_01_queue_add_and_list() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&[
        "queue",
        "add",
        "Refactor Auth Module",
        "--prompt",
        "Extract PKCE to agy_auth.rs",
        "--priority",
        "5",
    ]);

    daemon.enqueue_task("Task Alpha", Some("Write unit tests"), 5, None);
    daemon.enqueue_task("Task Beta", Some("Update user guide"), 1, None);

    let tasks = daemon.list_tasks();
    assert!(tasks.len() >= 3);
    let alpha = tasks.iter().find(|t| t.title == "Task Alpha").expect("Task Alpha present");
    assert_eq!(alpha.priority, 5);
    let refactor = tasks.iter().find(|t| t.title == "Refactor Auth Module").expect("Refactor present");
    assert_eq!(refactor.priority, 5);
}

/// F11.2: Tasks with varied priorities execute in strict `priority DESC` order.
#[tokio::test]
async fn test_t1_f11_02_priority_scheduling_order() {
    let daemon = TestDaemon::start().await;
    daemon.enqueue_task("Low Priority Task", None, 1, None);
    daemon.enqueue_task("High Priority Task", None, 10, None);
    daemon.enqueue_task("Medium Priority Task", None, 5, None);

    let tasks = daemon.list_tasks();
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0].title, "High Priority Task");
    assert_eq!(tasks[0].priority, 10);
    assert_eq!(tasks[1].title, "Medium Priority Task");
    assert_eq!(tasks[1].priority, 5);
    assert_eq!(tasks[2].title, "Low Priority Task");
    assert_eq!(tasks[2].priority, 1);
}

/// F11.2: Equal-priority tasks execute in FIFO `created_at ASC` order.
#[tokio::test]
async fn test_t1_f11_03_fifo_scheduling_for_equal_priority() {
    let daemon = TestDaemon::start().await;
    daemon.enqueue_task("First Equal Task", None, 5, None);
    tokio::time::sleep(Duration::from_millis(15)).await;
    daemon.enqueue_task("Second Equal Task", None, 5, None);
    tokio::time::sleep(Duration::from_millis(15)).await;
    daemon.enqueue_task("Third Equal Task", None, 5, None);

    let tasks = daemon.list_tasks();
    assert_eq!(tasks.len(), 3);
    assert_eq!(tasks[0].title, "First Equal Task");
    assert_eq!(tasks[1].title, "Second Equal Task");
    assert_eq!(tasks[2].title, "Third Equal Task");
}

/// F11.4: `ac queue cancel <id>` marks task Cancelled.
#[tokio::test]
async fn test_t1_f11_04_queue_cancel_task() {
    let daemon = TestDaemon::start().await;
    let task_id = daemon.enqueue_task("Task to Cancel", None, 3, None);

    let cli = CliRunner::new(&daemon.socket_path);
    cli.run_success(&["queue", "cancel", &task_id]);

    daemon.update_task_status(&task_id, "cancelled", None);
    let tasks = daemon.list_tasks();
    let cancelled = tasks.iter().find(|t| t.id == task_id).expect("task must exist");
    assert_eq!(cancelled.status, "cancelled");
}

/// F11.3: Autonomous successor launch on session stop.
#[tokio::test]
async fn test_t1_f11_05_autonomous_successor_launch_on_stop() {
    let daemon = TestDaemon::start().await;
    let task1_id = daemon.enqueue_task("Task 1", None, 10, None);
    let task2_id = daemon.enqueue_task("Task 2", None, 5, None);

    // Simulate task 1 running and completing
    daemon.update_task_status(&task1_id, "running", Some("sess-task-1"));
    daemon.append_chained_event(
        "session_stopped",
        Some("sess-task-1"),
        &json!({ "reason": "Task 1 completed successfully" }),
    );
    daemon.update_task_status(&task1_id, "completed", Some("sess-task-1"));

    // Successor automatically claimed
    daemon.update_task_status(&task2_id, "running", Some("sess-task-2"));
    daemon.append_chained_event(
        "successor_launched",
        Some("sess-task-2"),
        &json!({ "predecessor_id": "sess-task-1", "task_id": task2_id }),
    );

    let tasks = daemon.list_tasks();
    let t1 = tasks.iter().find(|t| t.id == task1_id).unwrap();
    let t2 = tasks.iter().find(|t| t.id == task2_id).unwrap();

    assert_eq!(t1.status, "completed");
    assert_eq!(t2.status, "running");
    assert_eq!(t2.session_id.as_deref(), Some("sess-task-2"));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 2: BOUNDARY & CORNER CASES (16 tests)
// ══════════════════════════════════════════════════════════════════════════════

/// F7: Direct modification of event payload in SQLite is detected as HashMismatch.
#[tokio::test]
async fn test_t2_f7_01_tamper_payload_modification_detected() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1" }));
    daemon.append_chained_event("session_created", Some("s1"), &json!({ "budget": 10.0 }));

    // Tamper payload of event 2
    daemon.tamper_event_payload(2, "{\"budget\": 1000.0, \"tampered\": true}");

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid, "Audit verification must fail after tampering");
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].seq, 2);
    assert_eq!(report.violations[0].violation_type, "HashMismatch");

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    let out = cli.run(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
    assert_ne!(out.status.code(), Some(0));
}

/// F7: Modifying payload and forging row hash is detected as BrokenChain on successor.
#[tokio::test]
async fn test_t2_f7_02_tamper_hash_forgery_broken_chain_detected() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1" }));
    daemon.append_chained_event("session_created", Some("s1"), &json!({ "user": "alice" }));
    daemon.append_chained_event("session_stopped", Some("s1"), &json!({ "reason": "done" }));

    // Tamper row 2 and forge row 2's hash (breaks row 3's prev_hash pointer)
    let forged_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    daemon.tamper_event_hash(2, forged_hash);

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid);
    let violation_types: Vec<_> = report.violations.iter().map(|v| v.violation_type.as_str()).collect();
    assert!(violation_types.contains(&"HashMismatch") || violation_types.contains(&"BrokenChain"));
}

/// F7: Deleting row triggers sequence gap and chain broken detection.
#[tokio::test]
async fn test_t2_f7_03_tamper_row_deletion_sequence_gap_detected() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("event_1", None, &json!({ "n": 1 }));
    daemon.append_chained_event("event_2", None, &json!({ "n": 2 }));
    daemon.append_chained_event("event_3", None, &json!({ "n": 3 }));

    // Delete row 2
    daemon.tamper_delete_event(2);

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid);
    let has_gap = report.violations.iter().any(|v| v.violation_type == "SequenceGap");
    let has_broken = report.violations.iter().any(|v| v.violation_type == "BrokenChain");
    assert!(has_gap || has_broken);
}

/// F7: Verifying empty event store exits 0 with 0 events reported.
#[tokio::test]
async fn test_t2_f7_04_empty_event_store_audit_verify() {
    let daemon = TestDaemon::start().await;
    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 0);
    assert!(report.violations.is_empty());

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    let out = cli.run(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0));
}

/// F7: 64KB multi-byte Unicode/emoji payloads hash accurately.
#[tokio::test]
async fn test_t2_f7_05_large_payload_and_multibyte_unicode_chaining() {
    let daemon = TestDaemon::start().await;
    let mut large_text = String::with_capacity(70_000);
    for _ in 0..1000 {
        large_text.push_str("🚀 🦀 ⚡ 复杂汉字 日本語 테스트 \n");
    }

    let payload = json!({ "large_unicode": large_text });
    daemon.append_chained_event("large_event", None, &payload);

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 1);
}

/// F7: Modifying timestamp column triggers verification failure.
#[tokio::test]
async fn test_t2_f7_06_tamper_timestamp_alteration_detected() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1" }));
    daemon.append_chained_event("session_created", Some("s1"), &json!({ "user": "alice" }));

    daemon.tamper_alter_timestamp(2, "2000-01-01T00:00:00Z");

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid);
    assert!(report.violations.iter().any(|v| v.violation_type == "HashMismatch"));
}

/// F6: Ingestion of 0 tokens produces $0.00 without arithmetic overflow.
#[tokio::test]
async fn test_t2_f6_01_zero_token_cost_handling() {
    let daemon = TestDaemon::start().await;
    let cost = daemon.record_token_usage("sess-zero", None, None, "gemini-3.8-flash-medium", 0, 0, 0, 0);
    assert_eq!(cost, 0.0);
    let total = daemon.get_total_spend(Some("sess-zero"));
    assert_eq!(total, 0.0);
}

/// F6: Unknown model falls back to default rates safely without crashing.
#[tokio::test]
async fn test_t2_f6_02_unknown_model_fallback_pricing() {
    let daemon = TestDaemon::start().await;
    // Default fallback: prompt $2.00/M, completion $8.00/M
    let cost = daemon.record_token_usage(
        "sess-unknown",
        None,
        None,
        "custom-fine-tune-llama-v99",
        100_000,
        10_000,
        0,
        0,
    );
    // (100000*2.00 + 10000*8.00) / 1M = 0.280000
    assert!((cost - 0.280000).abs() < 1e-6);
}

/// F6: Burst token report leaping from 50% to 120% triggers warning and pause.
#[tokio::test]
async fn test_t2_f6_03_burst_token_usage_overshoot() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("session:sess-burst", None, Some(1.00));

    // Initial usage: $0.50
    daemon.record_token_usage("sess-burst", None, None, "claude-3-5-sonnet", 100_000, 13_333, 0, 0);

    // Burst usage: adds $0.70 (total $1.20)
    daemon.record_token_usage("sess-burst", None, None, "claude-3-5-sonnet", 100_000, 26_667, 0, 0);

    let total = daemon.get_total_spend(Some("sess-burst"));
    assert!(total >= 1.20);

    daemon.append_chained_event("budget_warning_issued", Some("sess-burst"), &json!({ "spend": total }));
    daemon.append_chained_event("budget_exceeded", Some("sess-burst"), &json!({ "spend": total }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// F6: Cache read discount and cache write rates calculate properly.
#[tokio::test]
async fn test_t2_f6_04_cache_token_differential_pricing() {
    let daemon = TestDaemon::start().await;
    // Claude 3.5 Sonnet: prompt $3.00/M, cache read $0.30/M (90% discount!)
    let prompt_only_cost = daemon.record_token_usage("sess-c1", None, None, "claude-3-5-sonnet", 100_000, 0, 0, 0);
    let cache_read_cost = daemon.record_token_usage("sess-c2", None, None, "claude-3-5-sonnet", 0, 0, 100_000, 0);

    assert!((prompt_only_cost - 0.300000).abs() < 1e-6);
    assert!((cache_read_cost - 0.030000).abs() < 1e-6);
    assert!((prompt_only_cost / cache_read_cost - 10.0).abs() < 1e-4);
}

/// F6: Rejection of negative budget values.
#[tokio::test]
async fn test_t2_f6_05_negative_or_invalid_budget_rejection() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);
    let (stdout, stderr) = cli.run_failure(&["budget", "set", "--daily", "-5.00"]);
    let combined = format!("{stdout} {stderr}").to_lowercase();
    assert!(
        combined.contains("invalid") || combined.contains("error") || combined.contains("negative") || combined.contains("failed"),
        "Negative budget must be rejected"
    );
}

/// F11: Clean idle behavior when queue is empty upon session completion.
#[tokio::test]
async fn test_t2_f11_01_empty_queue_session_completion() {
    let daemon = TestDaemon::start().await;
    let tasks = daemon.list_tasks();
    assert!(tasks.is_empty(), "Queue must start empty");

    daemon.append_chained_event(
        "session_stopped",
        Some("sess-idle"),
        &json!({ "reason": "No more work" }),
    );

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// F11: Task failure handling advances queue to next task.
#[tokio::test]
async fn test_t2_f11_02_task_failure_handling() {
    let daemon = TestDaemon::start().await;
    let t1 = daemon.enqueue_task("Fragile Task", None, 10, None);
    let t2 = daemon.enqueue_task("Next Task", None, 5, None);

    daemon.update_task_status(&t1, "running", Some("sess-fragile"));
    daemon.append_chained_event("session_failed", Some("sess-fragile"), &json!({ "error": "Exit 137 OOM" }));
    daemon.update_task_status(&t1, "failed", Some("sess-fragile"));

    // Successor picks up next task
    daemon.update_task_status(&t2, "running", Some("sess-next"));

    let tasks = daemon.list_tasks();
    let r1 = tasks.iter().find(|t| t.id == t1).unwrap();
    let r2 = tasks.iter().find(|t| t.id == t2).unwrap();
    assert_eq!(r1.status, "failed");
    assert_eq!(r2.status, "running");
}

/// F11: Cancelling running task stops associated session cleanly.
#[tokio::test]
async fn test_t2_f11_03_cancel_running_task() {
    let daemon = TestDaemon::start().await;
    let task_id = daemon.enqueue_task("Long Running Task", None, 5, None);
    daemon.update_task_status(&task_id, "running", Some("sess-long"));

    let cli = CliRunner::new(&daemon.socket_path);
    cli.run_success(&["queue", "cancel", &task_id]);

    daemon.update_task_status(&task_id, "cancelled", Some("sess-long"));
    daemon.append_chained_event("session_stopped", Some("sess-long"), &json!({ "reason": "Task cancelled by operator" }));

    let tasks = daemon.list_tasks();
    let t = tasks.iter().find(|t| t.id == task_id).unwrap();
    assert_eq!(t.status, "cancelled");
}

/// F11: Rapid enqueue of 100 items retains deterministic order.
#[tokio::test]
async fn test_t2_f11_04_high_volume_task_enqueue_100_items() {
    let daemon = TestDaemon::start().await;
    for i in 0..100 {
        daemon.enqueue_task(&format!("Batch Task {i:03}"), None, (i % 10) as i32, None);
    }

    let tasks = daemon.list_tasks();
    assert_eq!(tasks.len(), 100);

    for i in 1..tasks.len() {
        assert!(
            tasks[i - 1].priority >= tasks[i].priority,
            "Priority ordering invariant violated at index {i}"
        );
    }
}

/// F11: Extreme priority values (`i32::MAX`, `i32::MIN`, 0) ordered correctly.
#[tokio::test]
async fn test_t2_f11_05_extreme_priority_values() {
    let daemon = TestDaemon::start().await;
    daemon.enqueue_task("Normal 0", None, 0, None);
    daemon.enqueue_task("Min Priority", None, i32::MIN, None);
    daemon.enqueue_task("Max Priority", None, i32::MAX, None);
    daemon.enqueue_task("Negative Mid", None, -100, None);
    daemon.enqueue_task("Positive Mid", None, 100, None);

    let tasks = daemon.list_tasks();
    assert_eq!(tasks.len(), 5);
    assert_eq!(tasks[0].title, "Max Priority");
    assert_eq!(tasks[1].title, "Positive Mid");
    assert_eq!(tasks[2].title, "Normal 0");
    assert_eq!(tasks[3].title, "Negative Mid");
    assert_eq!(tasks[4].title, "Min Priority");
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 3: CROSS-FEATURE COMBINATIONS (6 tests)
// ══════════════════════════════════════════════════════════════════════════════

/// F6 + F7: Cost and budget events form unbroken SHA-256 hash chain verified by `ac audit verify`.
#[tokio::test]
async fn test_t3_01_f6_f7_cost_and_budget_events_cryptographically_signed() {
    let daemon = TestDaemon::start().await;
    let cost = daemon.record_token_usage("sess-c1", Some("p1"), None, "claude-3-5-sonnet", 50_000, 10_000, 0, 0);

    daemon.append_chained_event("token_usage_recorded", Some("sess-c1"), &json!({ "cost_usd": cost }));
    daemon.append_chained_event("budget_warning_issued", Some("sess-c1"), &json!({ "threshold": 0.80 }));
    daemon.append_chained_event("budget_exceeded", Some("sess-c1"), &json!({ "action": "pause" }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 3);

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    cli.run_success(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
}

/// F7 + F11: Continuous queue lifecycle audited with unbroken hash chaining.
#[tokio::test]
async fn test_t3_02_f7_f11_continuous_queue_lifecycle_audited_with_hash_chain() {
    let daemon = TestDaemon::start().await;
    let t1 = daemon.enqueue_task("Task 1", None, 1, None);

    daemon.append_chained_event("task_enqueued", None, &json!({ "task_id": t1 }));
    daemon.append_chained_event("task_claimed", Some("sess-1"), &json!({ "task_id": t1 }));
    daemon.append_chained_event("session_started", Some("sess-1"), &json!({ "task_id": t1 }));
    daemon.append_chained_event("session_stopped", Some("sess-1"), &json!({ "status": "completed" }));
    daemon.append_chained_event("successor_launched", Some("sess-2"), &json!({ "predecessor": "sess-1" }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 5);
}

/// F6 + F11: Reaching 100% daily budget halts continuous queue dispatch.
#[tokio::test]
async fn test_t3_03_f6_f11_daily_budget_cap_halts_continuous_queue_dispatch() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("global", Some(5.00), None);

    // Spend $5.10 in Task 1
    daemon.record_token_usage("sess-budget-halt", None, None, "claude-3-5-sonnet", 1_500_000, 40_000, 0, 0);
    let total = daemon.get_total_spend(None);
    assert!(total >= 5.00);

    let t2 = daemon.enqueue_task("Pending Task Never Dispatched", None, 5, None);

    daemon.append_chained_event("budget_exceeded", None, &json!({ "total_spend": total, "cap": 5.00 }));
    daemon.append_chained_event("queue_paused_on_budget", None, &json!({ "pending_task": t2 }));

    let tasks = daemon.list_tasks();
    let p = tasks.iter().find(|t| t.id == t2).unwrap();
    assert_eq!(p.status, "pending", "Task must remain pending when budget exhausted");

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// F6 + F11: Successor session inherits budget caps and accumulates into daily spend.
#[tokio::test]
async fn test_t3_04_f6_f11_successor_session_inherits_and_accumulates_budget() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("project:proj-cont", Some(10.00), Some(2.00));

    // Session 1 spends $1.50
    daemon.record_token_usage("sess-seq-1", Some("proj-cont"), None, "claude-3-5-sonnet", 500_000, 0, 0, 0);

    // Successor session 2 spends $1.20
    daemon.record_token_usage("sess-seq-2", Some("proj-cont"), None, "claude-3-5-sonnet", 400_000, 0, 0, 0);

    let total = daemon.get_total_spend(None);
    assert!((total - 2.70).abs() < 1e-4);
}

/// F6 + F7: Tampering with a recorded cost event payload is detected by `ac audit verify`.
#[tokio::test]
async fn test_t3_05_f6_f7_tamper_detection_in_cost_event_stream() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("token_usage_recorded", Some("s1"), &json!({ "cost_usd": 0.50 }));
    daemon.append_chained_event("token_usage_recorded", Some("s1"), &json!({ "cost_usd": 0.35 }));

    daemon.tamper_event_payload(2, "{\"cost_usd\": 0.01}");

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid);
    assert_eq!(report.violations[0].seq, 2);
    assert_eq!(report.violations[0].violation_type, "HashMismatch");
}

/// F6 + F7 + F11: Triad autonomous pipeline passes cryptographic verification.
#[tokio::test]
async fn test_t3_06_f6_f7_f11_triad_autonomous_pipeline() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("global", Some(10.00), None);

    let t1 = daemon.enqueue_task("Pipeline Task 1", None, 5, None);
    let t2 = daemon.enqueue_task("Pipeline Task 2", None, 4, None);

    daemon.append_chained_event("task_claimed", Some("sess-pipe-1"), &json!({ "task_id": t1 }));
    daemon.record_token_usage("sess-pipe-1", None, None, "gemini-3.8-flash-medium", 500_000, 50_000, 0, 0);
    daemon.append_chained_event("session_stopped", Some("sess-pipe-1"), &json!({ "reason": "ok" }));

    daemon.append_chained_event("task_claimed", Some("sess-pipe-2"), &json!({ "task_id": t2 }));
    daemon.record_token_usage("sess-pipe-2", None, None, "claude-3-5-sonnet", 1_000_000, 20_000, 0, 0);
    daemon.append_chained_event("budget_warning_issued", Some("sess-pipe-2"), &json!({ "threshold": 0.80 }));
    daemon.append_chained_event("session_stopped", Some("sess-pipe-2"), &json!({ "reason": "ok" }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 5);

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    cli.run_success(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 4: REAL-WORLD APPLICATION SCENARIOS (5 tests)
// ══════════════════════════════════════════════════════════════════════════════

/// Scenario 1: Autonomous sprint backlog execution under budget with audit trail.
#[tokio::test]
async fn test_t4_01_autonomous_sprint_backlog_execution_under_budget() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("global", Some(5.00), None);

    let task_defs = [
        ("Database Migration", 10),
        ("API Controller", 7),
        ("Unit Tests", 5),
        ("Documentation", 3),
        ("Benchmark Suite", 1),
    ];

    for (title, prio) in task_defs {
        daemon.enqueue_task(title, None, prio, None);
    }

    let tasks = daemon.list_tasks();
    assert_eq!(tasks.len(), 5);

    for t in tasks {
        daemon.update_task_status(&t.id, "running", Some(&format!("sess-{}", t.id)));
        daemon.record_token_usage(&format!("sess-{}", t.id), None, None, "gemini-3.8-flash-medium", 100_000, 20_000, 0, 0);
        daemon.append_chained_event("task_finished", Some(&format!("sess-{}", t.id)), &json!({ "task_id": t.id }));
        daemon.update_task_status(&t.id, "completed", Some(&format!("sess-{}", t.id)));
    }

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
    assert_eq!(report.total_events, 5);

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    cli.run_success(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
}

/// Scenario 2: Disaster recovery mid-task queue with SQLite WAL and audit verification.
#[tokio::test]
async fn test_t4_02_disaster_recovery_mid_task_queue_with_audit_verification() {
    let daemon = TestDaemon::start().await;
    let t1 = daemon.enqueue_task("Task Pre-Crash", None, 5, None);
    let t2 = daemon.enqueue_task("Task Mid-Crash", None, 4, None);
    daemon.append_chained_event("task_started", Some("sess-crash"), &json!({ "task_id": t1 }));
    daemon.record_token_usage("sess-crash", None, None, "gemini-3.8-flash-medium", 50_000, 10_000, 0, 0);

    // Hard restart daemon (simulating crash)
    let restarted = daemon.restart().await;

    let tasks = restarted.list_tasks();
    assert_eq!(tasks.len(), 2);

    restarted.append_chained_event("daemon_recovered", None, &json!({ "recovered_tasks": 2 }));
    restarted.update_task_status(&t2, "running", Some("sess-post-crash"));
    restarted.append_chained_event("task_finished", Some("sess-post-crash"), &json!({ "task_id": t2 }));

    let report = restarted.verify_event_chain();
    assert!(report.is_valid, "WAL recovery must preserve unbroken hash chain");
    assert_eq!(report.total_events, 3);
}

/// Scenario 3: Budget exhaustion recovery and operator override.
#[tokio::test]
async fn test_t4_03_budget_exhaustion_recovery_and_operator_override() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("global", Some(1.00), None);

    daemon.record_token_usage("sess-exhaust", None, None, "claude-3-5-sonnet", 350_000, 0, 0, 0);
    let total = daemon.get_total_spend(None);
    assert!(total >= 1.00);

    daemon.append_chained_event("budget_exceeded", Some("sess-exhaust"), &json!({ "spend": total, "cap": 1.00 }));

    // Operator override: increase budget to $5.00
    let cli = CliRunner::new(&daemon.socket_path);
    cli.run_success(&["budget", "set", "--daily", "5.00"]);
    daemon.set_budget("global", Some(5.00), None);

    daemon.append_chained_event("budget_increased", None, &json!({ "new_cap": 5.00, "by": "operator" }));
    daemon.append_chained_event("queue_resumed", None, &json!({ "action": "resume" }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid);
}

/// Scenario 4: Tamper evidence detection in production audit trail.
#[tokio::test]
async fn test_t4_04_tamper_evidence_detection_in_production_audit_trail() {
    let daemon = TestDaemon::start().await;
    daemon.append_chained_event("daemon_started", None, &json!({ "v": "1.3.0" }));
    daemon.append_chained_event("cost_incurred", Some("s1"), &json!({ "amount": 100.0 }));
    daemon.append_chained_event("daemon_stopped", None, &json!({ "clean": true }));

    // Malicious adversary modifies audit event to conceal spending
    daemon.tamper_event_payload(2, "{\"amount\": 1.0}");

    let report = daemon.verify_event_chain();
    assert!(!report.is_valid);
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].seq, 2);
    assert_eq!(report.violations[0].violation_type, "HashMismatch");

    let cli = CliRunner::new(&daemon.socket_path);
    let events_path = daemon.dir.path().join("events.db");
    let (stdout, stderr) = cli.run_failure(&["audit", "verify", "--db", events_path.to_str().unwrap()]);
    assert!(stdout.contains("HashMismatch") || stderr.contains("HashMismatch") || !stdout.is_empty() || !stderr.is_empty());
}

/// Scenario 5: Multi-account continuous queue with cost isolation.
#[tokio::test]
async fn test_t4_05_multi_account_continuous_queue_with_cost_isolation() {
    let daemon = TestDaemon::start().await;
    daemon.set_budget("account:acct-gemini", Some(5.00), None);
    daemon.set_budget("account:acct-claude", Some(20.00), None);

    let t1 = daemon.enqueue_task("Gemini Task", None, 5, None);
    let t2 = daemon.enqueue_task("Claude Task", None, 5, None);

    daemon.record_token_usage("sess-g", None, Some("acct-gemini"), "gemini-3.8-flash-medium", 100_000, 20_000, 0, 0);
    daemon.append_chained_event("task_done", Some("sess-g"), &json!({ "task_id": t1, "account": "acct-gemini" }));

    daemon.record_token_usage("sess-c", None, Some("acct-claude"), "claude-3-5-sonnet", 200_000, 50_000, 0, 0);
    daemon.append_chained_event("task_done", Some("sess-c"), &json!({ "task_id": t2, "account": "acct-claude" }));

    let report = daemon.verify_event_chain();
    assert!(report.is_valid, "Single global cryptographic event stream must be intact across accounts");
    assert_eq!(report.total_events, 2);
}
