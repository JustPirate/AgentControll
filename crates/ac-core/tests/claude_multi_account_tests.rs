//! Integration tests for Claude Code Multi-Account Isolation (ADR-014).
//!
//! Verifies:
//! - Per-account home directory isolation (`~/.config/agentcontrol/profiles/<account-id>/`)
//! - Child process keyring isolation (`DBUS_SESSION_BUS_ADDRESS="disabled:"`)
//! - Zero ambient credential bleed from host environment
//! - Credential routing and storage via `ref:claude:...`
//! - Multi-account concurrent execution without state contamination
//! - Controlled session hand-off between Claude accounts
//! - Account profile and credential cleanup on removal

use std::sync::{Mutex, MutexGuard};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::{broadcast, mpsc};

use ac_core::{
    account_manager::{AccountManager, AccountStore},
    adapter::{
        claude::{ClaudeConfig, ClaudeMode},
        CompositeAdapterFactory,
    },
    credentials::{self, save_claude_credential},
    event_store::EventStore,
    ipc::IpcServer,
    project_registry::{ProjectRegistry, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    types::{Account, AdapterEvent, Id, SessionContext, SessionState},
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct TestEnv {
    _guard: MutexGuard<'static, ()>,
    tmp: TempDir,
}

impl TestEnv {
    fn new() -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempfile::tempdir().unwrap();
        let config_dir = tmp.path().join("config");
        let home_dir = tmp.path().join("home");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&home_dir).unwrap();

        std::env::set_var("HOME", &home_dir);
        std::env::set_var("XDG_CONFIG_HOME", &config_dir);

        // Inject ambient environment secrets to rigorously verify that they do NOT bleed
        std::env::set_var("ANTHROPIC_API_KEY", "leaked_ambient_anthropic_key_9999");
        std::env::set_var("ANTHROPIC_AUTH_TOKEN", "leaked_ambient_auth_token_9999");
        std::env::set_var("CLAUDE_API_KEY", "leaked_ambient_claude_key_9999");

        Self {
            _guard: guard,
            tmp,
        }
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        std::env::remove_var("ANTHROPIC_API_KEY");
        std::env::remove_var("ANTHROPIC_AUTH_TOKEN");
        std::env::remove_var("CLAUDE_API_KEY");
    }
}

#[derive(Debug, serde::Deserialize)]
struct TestIpcResponse {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

async fn send_ipc(
    sock_path: &std::path::Path,
    cmd: &str,
    params: serde_json::Value,
) -> TestIpcResponse {
    let stream = UnixStream::connect(sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let req = serde_json::json!({
        "v": 1,
        "id": "test_req",
        "cmd": cmd,
        "params": params,
    });
    let line = serde_json::to_string(&req).unwrap() + "\n";
    write_half.write_all(line.as_bytes()).await.unwrap();

    let mut reader = BufReader::new(read_half).lines();
    let resp_line = reader.next_line().await.unwrap().unwrap();
    serde_json::from_str(&resp_line).unwrap()
}

#[test]
fn test_claude_account_registration_and_credential_storage() {
    let _env = TestEnv::new();

    let cred_ref = save_claude_credential("Work Claude", "sk-ant-api03-work-key-12345").unwrap();
    assert!(cred_ref.starts_with("ref:claude:"));

    // Verify credential was stored on disk with mode 0600
    let cred_path = credentials::credential_path(&cred_ref).unwrap();
    assert!(cred_path.is_file());
    let content = std::fs::read_to_string(&cred_path).unwrap();
    assert!(content.contains("sk-ant-api03-work-key-12345"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&cred_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Register in AccountManager
    let store = AccountStore::open_in_memory().unwrap();
    let mut mgr = AccountManager::new(store).unwrap();

    let account = Account::new(
        "Work Claude".into(),
        "claude".into(),
        vec!["claude".into(), "claude-code".into()],
        cred_ref.clone(),
        2,
        vec!["work".into()],
    );
    let aid = account.id.clone();
    mgr.register(account).unwrap();

    let loaded = mgr.get(&aid).unwrap();
    assert_eq!(loaded.credential_ref, cred_ref);
    // Zero raw secret stored in Account entity
    assert!(!loaded.credential_ref.contains("sk-ant-"));
}

#[tokio::test]
async fn test_claude_child_process_isolation_and_zero_bleed() {
    let env = TestEnv::new();

    let cred_ref =
        save_claude_credential("Claude Account 1", "sk-ant-api03-isolated-token-1111").unwrap();
    let aid = Id::from("01JTESTACCT01");

    let log_file = env.tmp.path().join("claude_run.log");

    // Fake Claude CLI script capturing runtime environment
    let script = format!(
        r#"
printf 'HOME=%s\n' "$HOME" >> "{}"
printf 'KEY=%s\n' "${{ANTHROPIC_API_KEY:-UNSET}}" >> "{}"
printf 'TOKEN=%s\n' "${{ANTHROPIC_AUTH_TOKEN:-UNSET}}" >> "{}"
printf 'CLAUDE_KEY=%s\n' "${{CLAUDE_API_KEY:-UNSET}}" >> "{}"
printf 'DBUS=%s\n' "${{DBUS_SESSION_BUS_ADDRESS:-UNSET}}" >> "{}"
printf 'ACCT=%s\n' "${{AGENTCONTROL_ACCOUNT_ID:-UNSET}}" >> "{}"
printf 'CLAUDE_ACCT=%s\n' "${{CLAUDE_ACCOUNT_ID:-UNSET}}" >> "{}"
printf '{{"type": "completed", "summary": "Done"}}\n'
"#,
        log_file.display(),
        log_file.display(),
        log_file.display(),
        log_file.display(),
        log_file.display(),
        log_file.display(),
        log_file.display(),
    );

    let config = ClaudeConfig::custom("sh", vec!["-c".to_string(), script])
        .with_mode(ClaudeMode::Structured);

    let composite = CompositeAdapterFactory::new().with_claude_config(config);

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, _event_rx) = broadcast::channel(512);
    let event_store = EventStore::open_in_memory().unwrap();

    let account_store = AccountStore::open_in_memory().unwrap();
    let mut account_mgr = AccountManager::new(account_store).unwrap();
    let account = Account::new(
        "Claude Account 1".into(),
        "claude".into(),
        vec!["claude".into(), "claude-code".into()],
        cred_ref,
        2,
        vec![],
    );
    let mut account = account;
    account.id = aid.clone();
    account_mgr.register(account).unwrap();

    let project_store = ProjectStore::open_in_memory().unwrap();
    let project_reg = ProjectRegistry::new(project_store).unwrap();

    let session_mgr = SessionManager::new(event_store, cmd_rx, event_tx, 4, Box::new(composite))
        .with_account_manager(account_mgr)
        .with_project_registry(project_reg);

    tokio::spawn(async move { session_mgr.run().await });
    let session_mgr_handle = SessionManagerHandle::new(cmd_tx);

    let session_id = session_mgr_handle
        .create_with_context(
            "Test task".into(),
            "claude".into(),
            None,
            Some(aid.clone()),
        )
        .await
        .unwrap();

    session_mgr_handle.start(session_id).await.unwrap();

    // Wait for execution to finish
    tokio::time::sleep(Duration::from_millis(500)).await;

    let log_content = std::fs::read_to_string(&log_file).unwrap_or_default();

    let expected_profile = credentials::profile_dir(&aid).unwrap();
    assert!(
        log_content.contains(&format!("HOME={}", expected_profile.display())),
        "Child process HOME must point to per-account profile directory, got:\n{log_content}"
    );
    assert!(
        log_content.contains("KEY=sk-ant-api03-isolated-token-1111"),
        "ANTHROPIC_API_KEY must match account credential, got:\n{log_content}"
    );
    assert!(
        !log_content.contains("leaked_ambient_anthropic_key_9999"),
        "Ambient host ANTHROPIC_API_KEY must NOT bleed, got:\n{log_content}"
    );
    assert!(
        log_content.contains("TOKEN=UNSET"),
        "Ambient host ANTHROPIC_AUTH_TOKEN must be unset, got:\n{log_content}"
    );
    assert!(
        log_content.contains("CLAUDE_KEY=UNSET"),
        "Ambient host CLAUDE_API_KEY must be unset, got:\n{log_content}"
    );
    assert!(
        log_content.contains("DBUS=disabled:"),
        "DBUS_SESSION_BUS_ADDRESS must be 'disabled:', got:\n{log_content}"
    );
    assert!(
        log_content.contains(&format!("ACCT={}", aid.0)),
        "AGENTCONTROL_ACCOUNT_ID must be set, got:\n{log_content}"
    );
    assert!(
        log_content.contains(&format!("CLAUDE_ACCT={}", aid.0)),
        "CLAUDE_ACCOUNT_ID must be set, got:\n{log_content}"
    );

    // Verify profile filesystem structure
    assert!(expected_profile.join(".claude").is_dir());
    let claude_json = expected_profile.join(".claude.json");
    assert!(claude_json.is_file());
    let json_text = std::fs::read_to_string(&claude_json).unwrap();
    assert!(json_text.contains("sk-ant-api03-isolated-token-1111"));
}

#[tokio::test]
async fn test_claude_concurrent_multi_account_isolation() {
    let _env = TestEnv::new();

    let cred_a = save_claude_credential("Account Alpha", "key-alpha-111").unwrap();
    let aid_a = Id::from("01JALPHA000000000000000001");

    let cred_b = save_claude_credential("Account Beta", "key-beta-222").unwrap();
    let aid_b = Id::from("01JBETA0000000000000000002");

    let expected_prof_a = credentials::profile_dir(&aid_a).unwrap();
    let expected_prof_b = credentials::profile_dir(&aid_b).unwrap();

    let log_a = _env.tmp.path().join("claude_a.log");
    let log_b = _env.tmp.path().join("claude_b.log");

    let script_a = format!(
        r#"printf 'HOME=%s KEY=%s DBUS=%s\n' "$HOME" "${{ANTHROPIC_API_KEY:-UNSET}}" "${{DBUS_SESSION_BUS_ADDRESS:-UNSET}}" > "{}"
printf '{{"type": "completed", "summary": "Done A"}}\n'
"#,
        log_a.display()
    );
    let script_b = format!(
        r#"printf 'HOME=%s KEY=%s DBUS=%s\n' "$HOME" "${{ANTHROPIC_API_KEY:-UNSET}}" "${{DBUS_SESSION_BUS_ADDRESS:-UNSET}}" > "{}"
printf '{{"type": "completed", "summary": "Done B"}}\n'
"#,
        log_b.display()
    );

    let config_a = ClaudeConfig::custom("sh", vec!["-c".to_string(), script_a]);
    let config_b = ClaudeConfig::custom("sh", vec!["-c".to_string(), script_b]);

    let (tx_a, mut rx_a) = mpsc::channel(32);
    let (tx_b, mut rx_b) = mpsc::channel(32);

    let ctx_a = SessionContext::new(Id::new(), "Task A".into(), "claude".into())
        .with_account(aid_a.clone(), cred_a);
    let ctx_b = SessionContext::new(Id::new(), "Task B".into(), "claude".into())
        .with_account(aid_b.clone(), cred_b);

    let _h_a = ac_core::adapter::claude::ClaudeAdapter::spawn(&ctx_a, config_a, tx_a).unwrap();
    let _h_b = ac_core::adapter::claude::ClaudeAdapter::spawn(&ctx_b, config_b, tx_b).unwrap();

    let start = std::time::Instant::now();
    let mut done_a = false;
    let mut done_b = false;

    while start.elapsed() < Duration::from_secs(3) && (!done_a || !done_b) {
        if let Ok(Some(AdapterEvent::Completed { .. })) =
            tokio::time::timeout(Duration::from_millis(50), rx_a.recv()).await
        {
            done_a = true;
        }
        if let Ok(Some(AdapterEvent::Completed { .. })) =
            tokio::time::timeout(Duration::from_millis(50), rx_b.recv()).await
        {
            done_b = true;
        }
    }

    let out_a = std::fs::read_to_string(&log_a).unwrap();
    let out_b = std::fs::read_to_string(&log_b).unwrap();

    assert!(out_a.contains(&format!("HOME={}", expected_prof_a.display())));
    assert!(out_a.contains("KEY=key-alpha-111"));
    assert!(out_a.contains("DBUS=disabled:"));

    assert!(out_b.contains(&format!("HOME={}", expected_prof_b.display())));
    assert!(out_b.contains("KEY=key-beta-222"));
    assert!(out_b.contains("DBUS=disabled:"));

    // Mutual exclusivity - zero cross-bleed
    assert!(!out_a.contains("key-beta-222"));
    assert!(!out_b.contains("key-alpha-111"));
    assert!(!out_a.contains("leaked_ambient_anthropic_key_9999"));
    assert!(!out_b.contains("leaked_ambient_anthropic_key_9999"));
}

#[tokio::test]
async fn test_claude_controlled_session_handoff() {
    let _env = TestEnv::new();

    let cred_a = save_claude_credential("Account 1", "key-1").unwrap();
    let aid_a = Id::from("01JHANDOFFAAA");

    let cred_b = save_claude_credential("Account 2", "key-2").unwrap();
    let aid_b = Id::from("01JHANDOFFBBB");

    let account_store = AccountStore::open_in_memory().unwrap();
    let mut account_mgr = AccountManager::new(account_store).unwrap();
    let mut acct_a = Account::new("Account 1".into(), "claude".into(), vec!["claude".into()], cred_a, 2, vec![]);
    acct_a.id = aid_a.clone();
    account_mgr.register(acct_a).unwrap();

    let mut acct_b = Account::new("Account 2".into(), "claude".into(), vec!["claude".into()], cred_b, 2, vec![]);
    acct_b.id = aid_b.clone();
    account_mgr.register(acct_b).unwrap();

    let script = r#"
printf '{"type": "ready"}\n'
sleep 30
"#;
    let config = ClaudeConfig::custom("sh", vec!["-c".to_string(), script.to_string()]);
    let composite = CompositeAdapterFactory::new().with_claude_config(config);

    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, _event_rx) = broadcast::channel(512);
    let event_store = EventStore::open_in_memory().unwrap();

    let project_store = ProjectStore::open_in_memory().unwrap();
    let project_reg = ProjectRegistry::new(project_store).unwrap();

    let session_mgr = SessionManager::new(event_store, cmd_rx, event_tx, 4, Box::new(composite))
        .with_account_manager(account_mgr)
        .with_project_registry(project_reg);

    tokio::spawn(async move { session_mgr.run().await });
    let session_mgr_handle = SessionManagerHandle::new(cmd_tx);

    // Start on Account A
    let sess_a_id = session_mgr_handle
        .create_with_context("Continuous Work".into(), "claude".into(), None, Some(aid_a.clone()))
        .await
        .unwrap();

    session_mgr_handle.start(sess_a_id.clone()).await.unwrap();

    // Wait for working
    let mut working = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if let Ok(Some(sess)) = session_mgr_handle.get(sess_a_id.clone()).await {
            if sess.state == SessionState::Working {
                working = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(working, "Session A should become Working");

    // Perform controlled switch to Account B
    let successor_id = session_mgr_handle
        .switch_account(sess_a_id.clone(), aid_b.clone())
        .await
        .unwrap();

    // Verify lineage and handoff
    let old_sess = session_mgr_handle.get(sess_a_id).await.unwrap().unwrap();
    assert_eq!(old_sess.state, SessionState::HandedOff);
    assert_eq!(old_sess.successor_id, Some(successor_id.clone()));

    let new_sess = session_mgr_handle.get(successor_id).await.unwrap().unwrap();
    assert_eq!(new_sess.account_id, Some(aid_b));
    assert_eq!(new_sess.predecessor_id, Some(old_sess.id));
}

#[tokio::test]
async fn test_claude_account_removal_cleans_up_profile_and_credential() {
    let env = TestEnv::new();

    let cred_ref = save_claude_credential("Claude Account Removal", "sk-ant-removal-test").unwrap();
    let aid = Id::from("01JREMOVETEST01");

    // Prepare profile on disk
    let prof_dir = ac_core::adapter::claude::prepare_claude_profile(&aid, Some(&cred_ref)).unwrap();
    assert!(prof_dir.is_dir());

    let cred_path = credentials::credential_path(&cred_ref).unwrap();
    assert!(cred_path.is_file());

    // Setup IPC server
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut account_mgr = AccountManager::new(account_store).unwrap();
    let mut acct = Account::new(
        "Claude Account Removal".into(),
        "claude".into(),
        vec!["claude".into()],
        cred_ref.clone(),
        2,
        vec![],
    );
    acct.id = aid.clone();
    account_mgr.register(acct).unwrap();
    let account_handle = ac_core::account_manager::AccountManagerHandle::new(account_mgr);

    let event_store = EventStore::open_in_memory().unwrap();
    let (cmd_tx, cmd_rx) = mpsc::channel(64);
    let (event_tx, _event_rx) = broadcast::channel(512);
    let composite = CompositeAdapterFactory::new();
    let session_mgr = SessionManager::new(event_store, cmd_rx, event_tx.clone(), 4, Box::new(composite))
        .with_account_manager_handle(account_handle.clone());

    tokio::spawn(async move { session_mgr.run().await });
    let session_mgr_handle = SessionManagerHandle::new(cmd_tx);

    let sock_path = env.tmp.path().join("test_claude_ipc.sock");
    let server = IpcServer::bind(&sock_path, session_mgr_handle, event_tx)
        .unwrap()
        .with_account_manager(account_handle);
    tokio::spawn(async move { server.run().await });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let resp = send_ipc(
        &sock_path,
        "account.remove",
        serde_json::json!({
            "account_id": aid.0,
        }),
    )
    .await;

    assert!(resp.ok, "account.remove must succeed: {:?}", resp.error);

    // Profile and credential file must be removed from disk
    assert!(!prof_dir.exists(), "Profile directory should be deleted on account removal");
    assert!(!cred_path.exists(), "Credential file should be deleted on account removal");
}
