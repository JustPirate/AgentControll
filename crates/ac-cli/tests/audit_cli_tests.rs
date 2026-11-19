//! Integration test suite for Cryptographic Audit Log Signing (Milestone 1 / F7 / ADR-010).

use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::broadcast;

use ac_cli::client::DaemonClient;
use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    adapter::mock::MockAdapterFactory,
    event_store::{compute_event_hash, EventStore},
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::IpcServer,
    policy_engine::{PolicyEngine, PolicyStore},
    project_registry::{ProjectRegistry, ProjectRegistryHandle, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    types::{AgentEvent, AuditIntegrityReport, EventKind, IntegrityViolation},
};
use rusqlite::params;
use serde_json::json;

fn run_ac(args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ac"));
    cmd.env("DBUS_SESSION_BUS_ADDRESS", "disabled:");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to execute ac binary")
}

fn create_valid_test_db(path: &Path, count: usize) {
    let mut store = EventStore::open(path).expect("failed to open event store");
    for i in 1..=count {
        let mut e = AgentEvent::new(
            EventKind::DaemonStarted,
            None,
            json!({ "step": i, "desc": format!("audit event {i}") }),
            "system",
        );
        store.append(&mut e).expect("failed to append event");
    }
}

async fn setup_test_daemon(
    db_path: &Path,
) -> (DaemonClient, tempfile::TempDir, SessionManagerHandle) {
    let tmp = tempdir().unwrap();
    let sock = tmp.path().join("test_agentcontrol.sock");

    let store = EventStore::open(db_path).unwrap();
    let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);

    let pol_store = PolicyStore::open(&tmp.path().join("policies.db")).unwrap();
    let policy_engine = PolicyEngine::new(pol_store).unwrap();

    let int_store = InteractionStore::open(&tmp.path().join("interactions.db")).unwrap();
    let hub = InteractionHub::new(int_store, policy_engine).unwrap();
    let hub_handle = InteractionHubHandle::new(hub);

    let acct_store = AccountStore::open(&tmp.path().join("accounts.db")).unwrap();
    let mut acct_mgr = AccountManager::new(acct_store).unwrap();
    let acct = ac_core::types::Account::new(
        "Mock Account".into(),
        "mock-provider".into(),
        vec!["mock".into(), "agy".into()],
        "cred-1".into(),
        10,
        vec![],
    );
    acct_mgr.register(acct).unwrap();
    let acct_handle = AccountManagerHandle::new(acct_mgr);

    let proj_store = ProjectStore::open(&tmp.path().join("projects.db")).unwrap();
    let proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_handle = ProjectRegistryHandle::new(proj_reg);

    let factory = Box::new(MockAdapterFactory::always(vec![
        ac_core::adapter::mock::ScriptedEvent::immediate(ac_core::types::AdapterEvent::Ready),
    ]));
    let session_mgr = SessionManager::new(store, cmd_rx, event_tx.clone(), 3, factory)
        .with_account_manager_handle(acct_handle.clone())
        .with_project_registry_handle(proj_handle.clone())
        .with_interaction_hub(hub_handle.clone());

    tokio::spawn(async move {
        let sm = session_mgr;
        sm.run().await;
    });

    let mgr_handle = SessionManagerHandle::new(cmd_tx);

    let server = IpcServer::bind(&sock, mgr_handle.clone(), event_tx)
        .unwrap()
        .with_account_manager(acct_handle.clone())
        .with_project_registry(proj_handle.clone())
        .with_interaction_hub(hub_handle.clone());

    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = DaemonClient::new(sock);
    (client, tmp, mgr_handle)
}

#[test]
fn test_cli_audit_verify_valid_human() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("valid_events.db");
    create_valid_test_db(&db_path, 5);

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str]);

    assert!(output.status.success(), "Command should exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Audit Log Hash-Chain Integrity Report:"));
    assert!(stdout.contains("Status:          VALID"));
    assert!(stdout.contains("Total Events:    5"));
    assert!(stdout.contains("Verified Events: 5"));
    assert!(stdout.contains("Violations:      0"));
}

#[test]
fn test_cli_audit_verify_valid_json() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("valid_json_events.db");
    create_valid_test_db(&db_path, 5);

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str, "--json"]);

    assert!(output.status.success(), "Command should exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: AuditIntegrityReport =
        serde_json::from_str(&stdout).expect("Failed to parse JSON AuditIntegrityReport");

    assert!(report.is_valid);
    assert_eq!(report.total_events, 5);
    assert_eq!(report.verified_events, 5);
    assert_eq!(report.first_seq, Some(1));
    assert_eq!(report.last_seq, Some(5));
    assert!(report.genesis_hash.is_some());
    assert!(report.latest_hash.is_some());
    assert!(report.violations.is_empty());

    // Also test global flag `--json audit verify`
    let output_global = run_ac(&["--json", "audit", "verify", "--db", db_str]);
    assert!(output_global.status.success());
    let report_global: AuditIntegrityReport =
        serde_json::from_str(&String::from_utf8_lossy(&output_global.stdout))
            .expect("Failed to parse global JSON output");
    assert!(report_global.is_valid);
}

#[test]
fn test_cli_audit_verify_valid_plain() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("valid_plain_events.db");
    create_valid_test_db(&db_path, 5);

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str, "--plain"]);

    assert!(output.status.success(), "Command should exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2);
    assert_eq!(lines[0], "STATUS\tTOTAL\tFIRST_SEQ\tLAST_SEQ\tVIOLATIONS");
    assert_eq!(lines[1], "VALID\t5\t1\t5\t0");
}

#[test]
fn test_cli_audit_verify_tampered_payload_exit_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("tampered_payload.db");
    create_valid_test_db(&db_path, 5);

    // Tamper row 3's payload directly in SQLite
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE events SET payload = ?1 WHERE seq = 3",
            params![r#"{"tampered":true}"#],
        )
        .unwrap();
    }

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str]);

    assert!(!output.status.success(), "Command MUST exit with code 1");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CORRUPTED / TAMPERED"));
    assert!(stdout.contains("Hash mismatch at sequence 3"));
}

#[test]
fn test_cli_audit_verify_tampered_json_exit_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("tampered_json.db");
    create_valid_test_db(&db_path, 5);

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute(
            "UPDATE events SET payload = ?1 WHERE seq = 3",
            params![r#"{"tampered":true}"#],
        )
        .unwrap();
    }

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str, "--json"]);

    assert!(!output.status.success(), "Command MUST exit with code 1");
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: AuditIntegrityReport =
        serde_json::from_str(&stdout).expect("Failed to parse JSON report");

    assert!(!report.is_valid);
    assert_eq!(report.total_events, 5);
    assert_eq!(report.verified_events, 4);
    assert_eq!(report.violations.len(), 1);
    match &report.violations[0] {
        IntegrityViolation::HashMismatch { seq, .. } => {
            assert_eq!(*seq, 3);
        }
        other => panic!("expected HashMismatch, got {:?}", other),
    }
}

#[test]
fn test_cli_audit_verify_forged_hash_exit_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("forged_hash.db");
    create_valid_test_db(&db_path, 5);

    // Modify row 3's payload and recompute its hash so row 3 matches,
    // but row 4's prev_hash still holds the original row 3 hash
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let (prev_hash, ts, kind): (String, String, String) = conn
            .query_row(
                "SELECT prev_hash, timestamp, kind FROM events WHERE seq = 3",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();

        let forged_payload = r#"{"tampered":true}"#;
        let forged_hash = compute_event_hash(&prev_hash, 3, &ts, &kind, forged_payload);

        conn.execute(
            "UPDATE events SET payload = ?1, hash = ?2 WHERE seq = 3",
            params![forged_payload, forged_hash],
        )
        .unwrap();
    }

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str]);

    assert!(!output.status.success(), "Command MUST exit with code 1");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Broken hash chain at sequence 4"));
}

#[test]
fn test_cli_audit_verify_deleted_row_exit_1() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("deleted_row.db");
    create_valid_test_db(&db_path, 5);

    // Delete row 3
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute("DELETE FROM events WHERE seq = 3", []).unwrap();
    }

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str]);

    assert!(!output.status.success(), "Command MUST exit with code 1");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Sequence gap"));
}

#[test]
fn test_cli_audit_verify_empty_db() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("empty_events.db");
    // Open and close creates tables
    {
        let _store = EventStore::open(&db_path).unwrap();
    }

    let db_str = db_path.to_str().unwrap();
    let output = run_ac(&["audit", "verify", "--db", db_str]);

    assert!(output.status.success(), "Empty DB must exit with 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Status:          VALID"));
    assert!(stdout.contains("Total Events:    0"));
    assert!(stdout.contains("Violations:      0"));
}

#[tokio::test]
async fn test_daemon_ipc_audit_verify() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("daemon_events.db");
    create_valid_test_db(&db_path, 4);

    let (client, _tmp, _mgr) = setup_test_daemon(&db_path).await;

    let report = client
        .verify_audit()
        .await
        .expect("daemon audit verification failed");

    assert!(report.is_valid);
    assert_eq!(report.total_events, 4);
    assert_eq!(report.verified_events, 4);
    assert!(report.violations.is_empty());
}

#[tokio::test]
async fn test_cli_daemon_forwarding_and_fallback() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("forwarding_events.db");
    create_valid_test_db(&db_path, 3);

    let (client, _tmp, _mgr) = setup_test_daemon(&db_path).await;
    let sock_str = client.socket_path.to_str().unwrap();
    let db_str = db_path.to_str().unwrap();

    // 1. Explicit --db direct mode bypasses daemon
    let out_db = run_ac(&["--socket", sock_str, "audit", "verify", "--db", db_str]);
    assert!(out_db.status.success());
    assert!(String::from_utf8_lossy(&out_db.stdout).contains("VALID"));

    // 2. Explicit --offline flag direct mode
    let out_offline = run_ac(&["audit", "verify", "--offline", "--db", db_str]);
    assert!(out_offline.status.success());
    assert!(String::from_utf8_lossy(&out_offline.stdout).contains("VALID"));

    // 3. Unreachable socket falls back gracefully without panic when verifying DB
    let out_fallback = run_ac(&[
        "--socket",
        "/tmp/nonexistent_agentcontrol_test.sock",
        "audit",
        "verify",
        "--db",
        db_str,
    ]);
    assert!(out_fallback.status.success());
    assert!(String::from_utf8_lossy(&out_fallback.stdout).contains("VALID"));
}
