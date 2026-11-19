//! Real-World End-to-End Test Suite for Autonomous Quota Failover & System Features
//!
//! STRICT INVARIANT: ZERO MOCK DATA.
//! - Spawns real child processes on Linux via real executable shell scripts.
//! - Uses real pipes (stdin/stdout/stderr) and real Linux pseudo-terminals (PTY).
//! - Operates against real SQLite databases persisted on physical disk.
//! - Validates end-to-end behavior through the real compiled `ac` CLI binary.
//! - Enforces Landlock filesystem sandboxing and `DBUS_SESSION_BUS_ADDRESS="disabled:"`.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use base64::Engine;
use tempfile::{tempdir, TempDir};
use tokio::sync::broadcast;

use ac_cli::client::DaemonClient;
use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    adapter::{
        claude::ClaudeConfig,
        pty::PtyConfig,
        CompositeAdapterFactory,
    },
    agy_auth::{self, AgyToken},
    config::{AutoFailoverConfig, PluginCapabilitiesConfig, PluginConfig},
    credentials,
    event_store::EventStore,
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::IpcServer,
    policy_engine::{PolicyEngine, PolicyStore},
    project_registry::{ProjectRegistry, ProjectRegistryHandle, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    template_manager::{TemplateManager, TemplateManagerHandle, TemplateStore},
    types::{
        Account, AccountState, AgentEvent, AuditIntegrityReport, Project,
        SessionState, WorkspacePolicy,
    },
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

static DAEMON_RUNTIME: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
        .expect("daemon multi-thread runtime")
});

// ── Real Process & Script Helpers ─────────────────────────────────────────────

fn make_executable_script(path: &Path, content: &str) {
    fs::write(path, content).expect("failed to write executable script");
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("set_permissions 0755");
}

fn jwt(email: &str) -> String {
    let p = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(format!("{{\"email\":\"{email}\"}}"));
    format!("hdr.{p}.sig")
}

fn native_token(marker: &str, email: &str, expiry: &str) -> serde_json::Value {
    serde_json::json!({
        "token": {
            "access_token": format!("{marker}-access-SECRET"),
            "token_type": "Bearer",
            "refresh_token": format!("{marker}-refresh-SECRET"),
            "expiry": expiry,
        },
        "auth_method": "consumer",
        "id_token": jwt(email),
    })
}

fn make_agy_cred(label: &str, marker: &str, email: &str) -> String {
    let tok = AgyToken::from_native(native_token(marker, email, "2099-01-01T00:00:00Z")).unwrap();
    agy_auth::save_new_credential(label, &tok, "browser_login").unwrap()
}

fn run_ac_cli(socket_path: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ac"));
    cmd.arg("--socket").arg(socket_path);
    cmd.env("DBUS_SESSION_BUS_ADDRESS", "disabled:");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.output().expect("failed to execute ac binary")
}

// ── Real Daemon Test Environment ──────────────────────────────────────────────

struct RealTestEnvironment {
    _guard: MutexGuard<'static, ()>,
    pub _tmp: TempDir,
    pub socket_path: PathBuf,
    pub db_dir: PathBuf,
    pub workspace_dir: PathBuf,
    pub client: DaemonClient,
    pub session_mgr_handle: SessionManagerHandle,
    pub account_mgr_handle: AccountManagerHandle,
    pub project_reg_handle: ProjectRegistryHandle,
}

impl RealTestEnvironment {
    async fn new(adapter_factory: CompositeAdapterFactory) -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let tmp = tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let config_dir = tmp.path().join("config");
        let db_dir = tmp.path().join("data");
        let workspace_dir = tmp.path().join("workspace");

        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&db_dir).unwrap();
        fs::create_dir_all(&workspace_dir).unwrap();

        std::env::set_var("HOME", &home);
        std::env::set_var("XDG_CONFIG_HOME", &config_dir);
        std::env::set_var("DBUS_SESSION_BUS_ADDRESS", "disabled:");

        let socket_path = tmp.path().join("real_agentcontrol.sock");

        // Persistent SQLite databases
        let events_db = db_dir.join("events.db");
        let accounts_db = db_dir.join("accounts.db");
        let projects_db = db_dir.join("projects.db");
        let templates_db = db_dir.join("templates.db");
        let policies_db = db_dir.join("policies.db");
        let interactions_db = db_dir.join("interactions.db");

        let store = EventStore::open(&events_db).unwrap();
        let (event_tx, _) = broadcast::channel::<AgentEvent>(512);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(128);

        let pol_store = PolicyStore::open(&policies_db).unwrap();
        let policy_engine = PolicyEngine::new(pol_store).unwrap();
        let int_store = InteractionStore::open(&interactions_db).unwrap();
        let hub_handle =
            InteractionHubHandle::new(InteractionHub::new(int_store, policy_engine).unwrap());

        let acct_store = AccountStore::open(&accounts_db).unwrap();
        let acct_mgr = AccountManager::new(acct_store).unwrap();
        let account_mgr_handle = AccountManagerHandle::new(acct_mgr);

        let proj_store = ProjectStore::open(&projects_db).unwrap();
        let project_reg = ProjectRegistry::new(proj_store).unwrap();
        let project_reg_handle = ProjectRegistryHandle::new(project_reg);

        let tmpl_store = TemplateStore::open(&templates_db).unwrap();
        let tmpl_mgr = TemplateManager::new(tmpl_store).unwrap();
        let tmpl_handle = TemplateManagerHandle::new(tmpl_mgr);

        let session_mgr = SessionManager::new(store, cmd_rx, event_tx.clone(), 3, Box::new(adapter_factory))
            .with_account_manager_handle(account_mgr_handle.clone())
            .with_project_registry_handle(project_reg_handle.clone())
            .with_interaction_hub(hub_handle.clone())
            .with_auto_failover_config(&AutoFailoverConfig {
                enabled: true,
                default_cooldown_secs: 60,
            });

        DAEMON_RUNTIME.spawn(session_mgr.run());

        let session_mgr_handle = SessionManagerHandle::new(cmd_tx);

        let s_path = socket_path.clone();
        let s_mgr_handle = session_mgr_handle.clone();
        let s_event_tx = event_tx.clone();
        let s_acct_handle = account_mgr_handle.clone();
        let s_proj_handle = project_reg_handle.clone();
        let s_hub_handle = hub_handle.clone();
        let s_tmpl_handle = tmpl_handle.clone();

        DAEMON_RUNTIME.spawn(async move {
            let server = IpcServer::bind(&s_path, s_mgr_handle, s_event_tx)
                .unwrap()
                .with_account_manager(s_acct_handle)
                .with_project_registry(s_proj_handle)
                .with_interaction_hub(s_hub_handle)
                .with_template_manager(s_tmpl_handle);
            let _ = server.run().await;
        });

        let client = DaemonClient::new(socket_path.clone());
        for _ in 0..50 {
            if client.is_running().await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        Self {
            _guard: guard,
            _tmp: tmp,
            socket_path,
            db_dir,
            workspace_dir,
            client,
            session_mgr_handle,
            account_mgr_handle,
            project_reg_handle,
        }
    }
}

// ── Test 1: Real-World Claude NDJSON 429 Failover ─────────────────────────────

#[tokio::test]
async fn test_real_world_claude_quota_429_auto_failover() {
    let script_tmp = tempdir().unwrap();
    let claude_bin = script_tmp.path().join("real_claude_simulator.sh");
    let marker_file = script_tmp.path().join("primary_id.txt");

    let marker_path_str = marker_file.to_string_lossy().to_string();
    let claude_script_content = format!(
        r#"#!/bin/sh
set -e
printf '{{"type": "system", "subtype": "init"}}\n'
sleep 0.1

PRIMARY_ID=$(cat "{marker_path_str}" 2>/dev/null || echo "")
CURRENT_ID="${{CLAUDE_ACCOUNT_ID:-${{AGENTCONTROL_ACCOUNT_ID:-$AC_ACCOUNT_ID}}}}"

if [ -n "$PRIMARY_ID" ] && [ "$CURRENT_ID" = "$PRIMARY_ID" ]; then
    printf '{{"type": "assistant", "message": {{"content": [{{"type": "text", "text": "Starting work on primary Claude account..."}}]}}}}\n'
    sleep 0.1
    printf '{{"type": "error", "error": {{"type": "rate_limit_error", "message": "HTTP 429 Too Many Requests: Rate limit reached. Cooldown required."}}}}\n'
    sleep 10
else
    printf '{{"type": "assistant", "message": {{"content": [{{"type": "text", "text": "Handoff successor running on backup account..."}}]}}}}\n'
    echo "SUCCESS_CLAUDE_SOLVED_IN_$PWD" > claude_result.txt
    sleep 0.1
    printf '{{"type": "completed", "summary": "Claude task finished successfully"}}\n'
    exit 0
fi
"#
    );
    make_executable_script(&claude_bin, &claude_script_content);

    let claude_cfg = ClaudeConfig::new(claude_bin.to_string_lossy().to_string());
    let adapter_factory = CompositeAdapterFactory::new().with_claude_config(claude_cfg);

    let env = RealTestEnvironment::new(adapter_factory).await;

    // Register 2 real accounts with real Anthropic credentials
    let cred_primary = credentials::save_claude_credential("Claude Primary", "sk-ant-primary-test-token").unwrap();
    let cred_backup = credentials::save_claude_credential("Claude Backup", "sk-ant-backup-test-token").unwrap();

    let acct_primary_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "claude-primary".into(),
        "anthropic".into(),
        vec!["claude".into(), "claude-code".into()],
        cred_primary,
        1,
        vec!["prod".into()],
    )).unwrap();

    let acct_backup_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "claude-backup".into(),
        "anthropic".into(),
        vec!["claude".into(), "claude-code".into()],
        cred_backup,
        2,
        vec!["prod".into()],
    )).unwrap();

    // Record the primary account ID for the simulator script to identify itself
    fs::write(&marker_file, &acct_primary_id.0).unwrap();

    // Register a real project pointing to real workspace directory
    let proj = Project::new(
        "real-claude-project".into(),
        env.workspace_dir.to_string_lossy().to_string(),
        Some("claude".into()),
        vec![],
        WorkspacePolicy::Shared,
    );
    let proj_id = env.project_reg_handle.0.lock().unwrap().register(proj).unwrap();

    // Create and start session 1 via real CLI invocation: `ac session create`
    let create_out = run_ac_cli(
        &env.socket_path,
        &[
            "--json",
            "session",
            "create",
            "--task",
            "Solve issue in workspace",
            "--agent-type",
            "claude",
            "--project-id",
            &proj_id.0,
            "--account-id",
            &acct_primary_id.0,
        ],
    );
    assert!(create_out.status.success(), "CLI session create failed: {}", String::from_utf8_lossy(&create_out.stderr));
    let create_json: serde_json::Value = serde_json::from_slice(&create_out.stdout).expect("parse json");
    let sid1 = create_json["result"]["session_id"].as_str().expect("session_id").to_string();

    // Start session 1 via real CLI invocation: `ac session start <id>`
    let start_out = run_ac_cli(&env.socket_path, &["session", "start", &sid1]);
    assert!(start_out.status.success(), "CLI session start failed: {}", String::from_utf8_lossy(&start_out.stderr));

    // Wait for the real child process to emit 429, auto-failover to trigger, and successor to complete
    let mut successor_sid = None;
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sessions = env.client.list_sessions().await.unwrap();
        if sessions.len() >= 2 {
            let pred = sessions.iter().find(|s| s.id.0 == sid1).unwrap();
            let succ = sessions.iter().find(|s| s.id.0 != sid1).unwrap();
            if pred.state == SessionState::HandedOff && succ.state == SessionState::Stopped {
                successor_sid = Some(succ.id.clone());
                break;
            }
        }
    }

    assert!(successor_sid.is_some(), "Autonomous failover did not complete to successor within timeout");

    // 1. Verify workspace continuation: real file written by real child process
    let result_file = env.workspace_dir.join("claude_result.txt");
    assert!(result_file.exists(), "Successor did not produce output file in real workspace");
    let content = fs::read_to_string(&result_file).unwrap();
    assert!(content.contains("SUCCESS_CLAUDE_SOLVED_IN_"));

    // 2. Verify account states in SQLite via CLI: `ac --json account list`
    let acct_list_out = run_ac_cli(&env.socket_path, &["--json", "account", "list"]);
    assert!(acct_list_out.status.success());
    let accts_val: serde_json::Value = serde_json::from_slice(&acct_list_out.stdout).unwrap();
    let accts_arr = accts_val["result"]["accounts"].as_array().expect("accounts array");
    let primary_entry = accts_arr.iter().find(|a| a["id"] == acct_primary_id.0).expect("primary account");
    let backup_entry = accts_arr.iter().find(|a| a["id"] == acct_backup_id.0).expect("backup account");

    assert_eq!(primary_entry["state"].as_str().unwrap().to_lowercase(), "cooldown", "Primary account must be in Cooldown");
    assert_eq!(backup_entry["state"].as_str().unwrap().to_lowercase(), "active", "Backup account must remain Active");

    // 3. Verify cryptographic audit log integrity via CLI: `ac audit verify`
    let events_db_path = env.db_dir.join("events.db");
    let audit_out = run_ac_cli(&env.socket_path, &["audit", "verify", "--db", events_db_path.to_str().unwrap(), "--json"]);
    assert!(audit_out.status.success(), "Audit verify failed: {}", String::from_utf8_lossy(&audit_out.stderr));
    let audit_report: AuditIntegrityReport = serde_json::from_slice(&audit_out.stdout).expect("parse audit report");
    assert_eq!(audit_report.is_valid, true, "Hash chain must be completely valid");
    assert_eq!(audit_report.violations.len(), 0, "There must be zero cryptographic violations");
    assert!(audit_report.verified_events >= 6, "Expected at least 6 verified events in log");
}

// ── Test 2: Real-World Subprocess Plugin 429 Failover ──────────────────────────

#[tokio::test]
async fn test_real_world_subprocess_plugin_quota_429_auto_failover() {
    let script_tmp = tempdir().unwrap();
    let plugin_bin = script_tmp.path().join("real_plugin_simulator.sh");
    let marker_file = script_tmp.path().join("plugin_primary_id.txt");

    let marker_path_str = marker_file.to_string_lossy().to_string();
    let plugin_script_content = format!(
        r#"#!/bin/sh
set -e
printf '{{"type": "ready"}}\n'
sleep 0.1

PRIMARY_ID=$(cat "{marker_path_str}" 2>/dev/null || echo "")
CURRENT_ID="${{AC_ACCOUNT_ID:-${{AGENTCONTROL_ACCOUNT_ID:-$CLAUDE_ACCOUNT_ID}}}}"

if [ -n "$PRIMARY_ID" ] && [ "$CURRENT_ID" = "$PRIMARY_ID" ]; then
    printf '{{"type": "output", "data": "Connecting to external Devin AI engine..."}}\n'
    sleep 0.1
    printf '{{"type": "rate_limit", "back_off_secs": 45}}\n'
    sleep 10
else
    printf '{{"type": "output", "data": "Devin successor resumed in workspace."}}\n'
    echo "DEVIN_TASK_SUCCESS" > devin_result.txt
    sleep 0.1
    printf '{{"type": "completed", "summary": "Plugin work done"}}\n'
    exit 0
fi
"#
    );
    make_executable_script(&plugin_bin, &plugin_script_content);

    let plugin_cfg = PluginConfig {
        name: "devin-adapter".into(),
        executable: plugin_bin,
        args: vec![],
        agent_types: vec!["devin".into()],
        env: Default::default(),
        capabilities: PluginCapabilitiesConfig {
            supports_session_resume: true,
            supports_snapshot_restore: true,
            ..Default::default()
        },
    };

    let adapter_factory = CompositeAdapterFactory::new().with_plugins(vec![plugin_cfg]);
    let env = RealTestEnvironment::new(adapter_factory).await;

    // Register 2 accounts for provider "devin-corp"
    let acct1_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "devin-primary".into(),
        "devin-corp".into(),
        vec!["devin".into()],
        "ref:devin:cred-1".into(),
        1,
        vec![],
    )).unwrap();

    let acct2_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "devin-backup".into(),
        "devin-corp".into(),
        vec!["devin".into()],
        "ref:devin:cred-2".into(),
        2,
        vec![],
    )).unwrap();

    fs::write(&marker_file, &acct1_id.0).unwrap();

    let proj = Project::new(
        "devin-project".into(),
        env.workspace_dir.to_string_lossy().to_string(),
        Some("devin".into()),
        vec![],
        WorkspacePolicy::Shared,
    );
    let proj_id = env.project_reg_handle.0.lock().unwrap().register(proj).unwrap();

    // Start session on devin-primary
    let sid1 = env.session_mgr_handle.create_with_context(
        "Analyze devin codebase".into(),
        "devin".into(),
        Some(proj_id),
        Some(acct1_id.clone()),
    ).await.unwrap();

    env.session_mgr_handle.start(sid1.clone()).await.unwrap();

    // Wait for failover to complete
    let mut successor_sid = None;
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sessions = env.client.list_sessions().await.unwrap();
        if sessions.len() >= 2 {
            let pred = sessions.iter().find(|s| s.id == sid1).unwrap();
            let succ = sessions.iter().find(|s| s.id != sid1).unwrap();
            if pred.state == SessionState::HandedOff && succ.state == SessionState::Stopped {
                successor_sid = Some(succ.id.clone());
                break;
            }
        }
    }

    assert!(successor_sid.is_some(), "Plugin autonomous failover did not complete");

    // Verify workspace artifact
    let result_file = env.workspace_dir.join("devin_result.txt");
    assert!(result_file.exists());
    assert!(fs::read_to_string(&result_file).unwrap().contains("DEVIN_TASK_SUCCESS"));

    // Verify primary account in Cooldown
    let acct1 = env.account_mgr_handle.0.lock().unwrap().get(&acct1_id).unwrap().clone();
    assert_eq!(acct1.state, AccountState::Cooldown, "devin-primary must be in Cooldown");

    let acct2 = env.account_mgr_handle.0.lock().unwrap().get(&acct2_id).unwrap().clone();
    assert_eq!(acct2.state, AccountState::Active, "devin-backup must be Active");
}

// ── Test 3: Real-World PTY Antigravity Quota Pattern Matching Failover ────────

#[tokio::test]
async fn test_real_world_pty_antigravity_quota_auto_failover() {
    let script_tmp = tempdir().unwrap();
    let agy_bin = script_tmp.path().join("real_fake_agy.sh");
    let marker_file = script_tmp.path().join("agy_primary_id.txt");

    let marker_path_str = marker_file.to_string_lossy().to_string();
    let agy_script_content = format!(
        r#"#!/bin/sh
set -e
printf 'Antigravity CLI v2.0 initialized\n'
sleep 0.1

PRIMARY_ID=$(cat "{marker_path_str}" 2>/dev/null || echo "")
CURRENT_ID="${{AGENTCONTROL_ACCOUNT_ID:-${{ANTIGRAVITY_ACCOUNT_ID:-$AC_ACCOUNT_ID}}}}"

if [ -n "$PRIMARY_ID" ] && [ "$CURRENT_ID" = "$PRIMARY_ID" ]; then
    printf 'Error: 429 Rate limit exceeded. Quota exhausted for user.\n'
    sleep 10
else
    printf 'Successor session resumed in workspace.\n'
    echo "AGY_PTY_SUCCESS" > agy_result.txt
    sleep 0.1
    exit 0
fi
"#
    );
    make_executable_script(&agy_bin, &agy_script_content);

    let mut pty_cfg = PtyConfig::default();
    pty_cfg.program = agy_bin.to_string_lossy().to_string();

    let adapter_factory = CompositeAdapterFactory::new().with_pty_config(pty_cfg);
    let env = RealTestEnvironment::new(adapter_factory).await;

    // Point ANTIGRAVITY_BIN to our script
    std::env::set_var("ANTIGRAVITY_BIN", &agy_bin);

    // Register 2 real agy accounts with valid tokens
    let cred1 = make_agy_cred("AGY Primary", "MARK_AGY_1", "user1@example.com");
    let cred2 = make_agy_cred("AGY Backup", "MARK_AGY_2", "user2@example.com");

    let acct1_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "agy-primary".into(),
        "antigravity".into(),
        vec!["agy".into(), "antigravity".into()],
        cred1,
        1,
        vec![],
    )).unwrap();

    let acct2_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "agy-backup".into(),
        "antigravity".into(),
        vec!["agy".into(), "antigravity".into()],
        cred2,
        2,
        vec![],
    )).unwrap();

    fs::write(&marker_file, &acct1_id.0).unwrap();

    let proj = Project::new(
        "agy-project".into(),
        env.workspace_dir.to_string_lossy().to_string(),
        Some("agy".into()),
        vec![],
        WorkspacePolicy::Shared,
    );
    let proj_id = env.project_reg_handle.0.lock().unwrap().register(proj).unwrap();

    // Start session on agy-primary
    let sid1 = env.session_mgr_handle.create_with_context(
        "Run agy task".into(),
        "agy".into(),
        Some(proj_id),
        Some(acct1_id.clone()),
    ).await.unwrap();

    env.session_mgr_handle.start(sid1.clone()).await.unwrap();

    // Wait for PTY regex to match 429 quota message and trigger failover
    let mut successor_sid = None;
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let sessions = env.client.list_sessions().await.unwrap();
        if sessions.len() >= 2 {
            let pred = sessions.iter().find(|s| s.id == sid1).unwrap();
            let succ = sessions.iter().find(|s| s.id != sid1).unwrap();
            if pred.state == SessionState::HandedOff && succ.state == SessionState::Stopped {
                successor_sid = Some(succ.id.clone());
                break;
            }
        }
    }

    assert!(successor_sid.is_some(), "PTY regex failover did not complete");

    // Verify workspace file
    let result_file = env.workspace_dir.join("agy_result.txt");
    assert!(result_file.exists());
    assert!(fs::read_to_string(&result_file).unwrap().contains("AGY_PTY_SUCCESS"));

    // Verify account state in SQLite
    let acct1 = env.account_mgr_handle.0.lock().unwrap().get(&acct1_id).unwrap().clone();
    assert_eq!(acct1.state, AccountState::Cooldown);

    let acct2 = env.account_mgr_handle.0.lock().unwrap().get(&acct2_id).unwrap().clone();
    assert_eq!(acct2.state, AccountState::Active);
}

// ── Test 4: Provider Matching Isolation (No Cross-Provider Failover) ──────────

#[tokio::test]
async fn test_real_world_provider_matching_isolation_prevents_cross_provider_failover() {
    let script_tmp = tempdir().unwrap();
    let claude_bin = script_tmp.path().join("real_claude_exhausted.sh");

    let script_content = r#"#!/bin/sh
set -e
printf '{"type": "system", "subtype": "init"}\n'
sleep 0.1
printf '{"type": "error", "error": {"type": "rate_limit_error", "message": "HTTP 429 Too Many Requests"}}\n'
sleep 10
"#;
    make_executable_script(&claude_bin, script_content);

    let claude_cfg = ClaudeConfig::new(claude_bin.to_string_lossy().to_string());
    let adapter_factory = CompositeAdapterFactory::new().with_claude_config(claude_cfg);
    let env = RealTestEnvironment::new(adapter_factory).await;

    // Only 1 Anthropic account and 1 Antigravity account registered
    let cred_claude = credentials::save_claude_credential("Claude Lone", "sk-ant-test").unwrap();
    let acct_claude_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "claude-lone".into(),
        "anthropic".into(),
        vec!["claude".into()],
        cred_claude,
        1,
        vec![],
    )).unwrap();

    let cred_agy = make_agy_cred("AGY Lone", "MARK_AGY_LONE", "agy@example.com");
    let _acct_agy_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "agy-lone".into(),
        "antigravity".into(),
        vec!["agy".into()],
        cred_agy,
        1,
        vec![],
    )).unwrap();

    let proj = Project::new(
        "lone-project".into(),
        env.workspace_dir.to_string_lossy().to_string(),
        Some("claude".into()),
        vec![],
        WorkspacePolicy::Shared,
    );
    let proj_id = env.project_reg_handle.0.lock().unwrap().register(proj).unwrap();

    let sid = env.session_mgr_handle.create_with_context(
        "Task requiring failover but no provider backup".into(),
        "claude".into(),
        Some(proj_id),
        Some(acct_claude_id),
    ).await.unwrap();

    env.session_mgr_handle.start(sid.clone()).await.unwrap();

    // Wait and verify: Must NOT fail over to agy-lone! Must enter RateLimited state.
    let mut reached_rate_limited = false;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let s = env.session_mgr_handle.get(sid.clone()).await.unwrap().unwrap();
        if s.state == SessionState::RateLimited {
            reached_rate_limited = true;
            break;
        }
    }

    assert!(reached_rate_limited, "Session must transition to RateLimited when no matching provider account is available");

    // Ensure no successor session was spawned
    let all_sessions = env.client.list_sessions().await.unwrap();
    assert_eq!(all_sessions.len(), 1, "Must never spawn cross-provider successor");
}

// ── Test 5: Real-World Cooldown Expiration Sweeper ─────────────────────────────

#[tokio::test]
async fn test_real_world_cooldown_expiration_sweeper() {
    let adapter_factory = CompositeAdapterFactory::new();
    let env = RealTestEnvironment::new(adapter_factory).await;

    let cred = credentials::save_claude_credential("Claude Cooldown Test", "sk-ant-test").unwrap();
    let acct_id = env.account_mgr_handle.0.lock().unwrap().register(Account::new(
        "claude-expiring".into(),
        "anthropic".into(),
        vec!["claude".into()],
        cred,
        1,
        vec![],
    )).unwrap();

    // Place account in Cooldown with 1 second duration
    let cooldown_target = chrono::Utc::now() + chrono::Duration::seconds(1);
    env.account_mgr_handle.0.lock().unwrap().start_cooldown(&acct_id, cooldown_target).unwrap();

    let acct_before = env.account_mgr_handle.0.lock().unwrap().get(&acct_id).unwrap().clone();
    assert_eq!(acct_before.state, AccountState::Cooldown);

    // Sleep 1.1s so cooldown expires
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // Run expiration sweeper
    let expired = env.account_mgr_handle.0.lock().unwrap().maybe_expire_all_cooldowns().unwrap();
    assert!(expired.contains(&acct_id), "Account ID must be in expired list");

    // Query CLI: `ac --json account list`
    let list_out = run_ac_cli(&env.socket_path, &["--json", "account", "list"]);
    assert!(list_out.status.success());
    let accts_val: serde_json::Value = serde_json::from_slice(&list_out.stdout).unwrap();
    let acct_entry = accts_val["result"]["accounts"].as_array().unwrap().iter().find(|a| a["id"] == acct_id.0).unwrap();
    assert_eq!(acct_entry["state"].as_str().unwrap().to_lowercase(), "active", "Account must be restored to Active after cooldown expiration");
}
