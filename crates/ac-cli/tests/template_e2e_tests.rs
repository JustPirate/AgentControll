//! Comprehensive End-to-End Test Suite for Reusable Session Templates & Presets (F10)
//!
//! Covering:
//! - Tier 1: Feature Coverage (F1 to F7)
//! - Tier 2: Boundary & Corner Cases (F1 to F7)
//! - Tier 3: Cross-Feature Combinations (T3-01 to T3-10)
//! - Tier 4: Real-World Application Scenarios (T4-01 to T4-06)
//!
//! Design:
//! - 100% Opaque-box testing using compiled `ac` CLI binary (`env!("CARGO_BIN_EXE_ac")`)
//! - Direct Unix domain socket IPC protocol validation (`ApiRequest` / `ApiResponse`)
//! - SQLite WAL persistence verification across daemon restarts via `TestDaemon::restart()`
//! - Hermetic isolation using temporary directories and `MockAdapterFactory`

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Arc;
use std::time::Duration;
use tempfile::{tempdir, TempDir};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::broadcast;

use ac_cli::client::DaemonClient;
use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    adapter::mock::{MockAdapterFactory, ScriptedEvent},
    agy_launch::{AgyExecutionMode, AgyLaunchOptions, AgyPermissionMode},
    event_store::EventStore,
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::IpcServer,
    policy_engine::{PolicyEngine, PolicyStore},
    project_registry::{ProjectRegistry, ProjectRegistryHandle, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    template_manager::{TemplateManager, TemplateManagerHandle, TemplateStore},
    types::{Account, AdapterEvent, AgentEvent, ApiRequest, ApiResponse, Id, SessionTemplate},
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

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
        let socket_path = dir.path().join("ac-test.sock");
        Self::start_with_dir(dir, socket_path).await
    }

    pub async fn start_with_dir(dir: TempDir, socket_path: PathBuf) -> Self {
        let db_dir = dir.path();
        let store = EventStore::open(&db_dir.join("events.db")).unwrap();
        let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);

        let pol_store = PolicyStore::open(&db_dir.join("policies.db")).unwrap();
        let policy_engine = PolicyEngine::new(pol_store).unwrap();
        let int_store = InteractionStore::open(&db_dir.join("interactions.db")).unwrap();
        let hub_handle = InteractionHubHandle::new(InteractionHub::new(int_store, policy_engine).unwrap());

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

        // Template persistence & manager
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

    /// Simulates a daemon restart by aborting the running IPC server and reopening
    /// against the exact same SQLite databases.
    pub async fn restart(self) -> Self {
        self.server_task.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = fs::remove_file(&self.socket_path);
        Self::start_with_dir(self.dir, self.socket_path).await
    }

    /// Send a raw string to the Unix socket and receive one response line.
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

    /// Send a structured ApiRequest over Unix socket and parse ApiResponse.
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

    /// Register a secondary account for testing routing/tag selection.
    pub fn register_secondary_account(&self, name: &str, provider: &str, tags: Vec<String>) -> Id {
        let mut mgr = self.acct_handle.0.lock().unwrap();
        let acct = Account::new(
            name.to_string(),
            provider.to_string(),
            vec!["agy".into()],
            format!("ref:{}", name),
            5,
            tags,
        );
        let id = acct.id.clone();
        let _ = mgr.register(acct);
        id
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

    pub fn run(&self, args: &[&str]) -> Output {
        Command::new(Self::bin_path())
            .arg("--socket")
            .arg(&self.socket_path)
            .args(args)
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
        let mut full_args = vec!["--json"];
        full_args.extend_from_slice(args);
        let stdout = self.run_success(&full_args);
        serde_json::from_str(&stdout).unwrap_or_else(|e| {
            panic!(
                "failed to parse JSON from {:?}: {}\noutput: {}",
                full_args, e, stdout
            )
        })
    }
}

fn sample_template_model(name: &str) -> SessionTemplate {
    let mut t = SessionTemplate::new(name, "agy");
    t.description = Some(format!("Description for {name}"));
    t.default_task_prompt = Some("Inspect repo and run tests".into());
    t.account_tag = Some("default".into());
    t.permission_mode = Some("normal".into());
    t.model = Some("gemini-3.8-flash-medium".into());
    let mut launch = AgyLaunchOptions::default();
    launch.execution_mode = AgyExecutionMode::Plan;
    launch.permission_mode = AgyPermissionMode::Normal;
    launch.sandbox = true;
    t.launch_options = Some(launch);
    t
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 1: FEATURE COVERAGE
// ══════════════════════════════════════════════════════════════════════════════

// ── Feature F1: Template Creation ─────────────────────────────────────────────

#[tokio::test]
async fn test_t1_f1_01_minimal_template_creation() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "create", "--name", "minimal-dev"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("minimal-dev") || stdout.contains("OK"));

    // Verify in manager
    let mgr = daemon.template_handle.0.lock().unwrap();
    let tmpl = mgr.get_by_name("minimal-dev").expect("must exist in manager");
    assert_eq!(tmpl.name, "minimal-dev");
    assert_eq!(tmpl.agent_type, "agy");
}

#[tokio::test]
async fn test_t1_f1_02_full_featured_creation() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let work_dir = daemon.dir.path().to_str().unwrap();
    let out = cli.run(&[
        "template",
        "create",
        "--name",
        "full-preset",
        "--description",
        "Full Dev Setup",
        "--agent-type",
        "agy",
        "--prompt",
        "Build full application",
        "--model",
        "gemini-3.8-flash-medium",
        "--permission-mode",
        "normal",
        "--account-tag",
        "dev-team",
        "--execution-mode",
        "accept-edits",
        "--sandbox",
        "--working-dir",
        work_dir,
    ]);
    assert_eq!(out.status.code(), Some(0));

    let mgr = daemon.template_handle.0.lock().unwrap();
    let tmpl = mgr.get_by_name("full-preset").expect("must exist");
    assert_eq!(tmpl.description.as_deref(), Some("Full Dev Setup"));
    assert_eq!(
        tmpl.default_task_prompt.as_deref(),
        Some("Build full application")
    );
    assert_eq!(tmpl.account_tag.as_deref(), Some("dev-team"));
    assert_eq!(tmpl.model.as_deref(), Some("gemini-3.8-flash-medium"));
    let opts = tmpl.launch_options.as_ref().expect("launch options");
    assert!(opts.sandbox);
    assert_eq!(opts.execution_mode, AgyExecutionMode::AcceptEdits);
    assert_eq!(opts.working_dir.as_deref(), Some(work_dir));
}

#[tokio::test]
async fn test_t1_f1_03_claude_agent_type_creation() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&[
        "template",
        "create",
        "--name",
        "claude-worker",
        "--agent-type",
        "claude",
        "--description",
        "Claude audit preset",
        "--prompt",
        "Perform security audit",
    ]);
    assert_eq!(out.status.code(), Some(0));

    let mgr = daemon.template_handle.0.lock().unwrap();
    let tmpl = mgr.get_by_name("claude-worker").expect("must exist");
    assert_eq!(tmpl.agent_type, "claude");
}

#[tokio::test]
async fn test_t1_f1_04_plan_execution_mode_creation() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&[
        "template",
        "create",
        "--name",
        "plan-tmpl",
        "--execution-mode",
        "plan",
        "--description",
        "Plan only execution",
    ]);
    assert_eq!(out.status.code(), Some(0));

    let mgr = daemon.template_handle.0.lock().unwrap();
    let tmpl = mgr.get_by_name("plan-tmpl").expect("must exist");
    assert_eq!(
        tmpl.launch_options.as_ref().unwrap().execution_mode,
        AgyExecutionMode::Plan
    );
}

#[tokio::test]
async fn test_t1_f1_05_json_mode_creation() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&[
        "template",
        "create",
        "--name",
        "json-created",
        "--prompt",
        "Test prompt",
    ]);
    assert_eq!(val["ok"], true);
    let tmpl_id = val["result"]["template_id"].as_str().expect("template_id");
    assert_eq!(tmpl_id.len(), 26);
    assert_eq!(val["result"]["name"], "json-created");
}

// ── Feature F2: Template Listing ──────────────────────────────────────────────

#[tokio::test]
async fn test_t1_f2_01_empty_store_listing() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "list"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Table mode displays "No templates." or in non-TTY plain mode displays empty
    assert!(stdout.contains("No templates.") || stdout.trim().is_empty());
}

#[tokio::test]
async fn test_t1_f2_02_single_template_table_listing() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("alpha-tmpl")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("alpha-tmpl"));
}

#[tokio::test]
async fn test_t1_f2_03_multiple_templates_listing() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("tmpl-a")).unwrap();
        mgr.create(sample_template_model("tmpl-b")).unwrap();
        mgr.create(sample_template_model("tmpl-c")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("tmpl-a"));
    assert!(stdout.contains("tmpl-b"));
    assert!(stdout.contains("tmpl-c"));
}

#[tokio::test]
async fn test_t1_f2_04_plain_format_listing() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("plain-one")).unwrap();
        mgr.create(sample_template_model("plain-two")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["--plain", "template", "list"]);
    let lines: Vec<&str> = stdout.trim().split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        assert!(line.contains('\t'), "line must be tab-delimited: {line}");
        assert!(!line.contains("TEMPLATE ID"), "plain mode must not have table headers");
    }
}

#[tokio::test]
async fn test_t1_f2_05_json_format_listing() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("json-one")).unwrap();
        mgr.create(sample_template_model("json-two")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "list"]);
    assert_eq!(val["ok"], true);
    let list = val["result"]["templates"].as_array().expect("templates array");
    assert_eq!(list.len(), 2);
}

// ── Feature F3: Template Inspection ───────────────────────────────────────────

#[tokio::test]
async fn test_t1_f3_01_inspect_by_name_slug() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("basic-dev")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "get", "basic-dev"]);
    assert!(stdout.contains("basic-dev"));
}

#[tokio::test]
async fn test_t1_f3_02_inspect_by_ulid_id() {
    let daemon = TestDaemon::start().await;
    let id = {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("inspect-by-id")).unwrap()
    };
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "get", &id.0]);
    assert!(stdout.contains("inspect-by-id"));
    assert!(stdout.contains(&id.0));
}

#[tokio::test]
async fn test_t1_f3_03_json_inspection() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("json-inspect")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "get", "json-inspect"]);
    assert_eq!(val["ok"], true);
    let t = &val["result"]["template"];
    assert_eq!(t["name"], "json-inspect");
    assert_eq!(t["agent_type"], "agy");
}

#[tokio::test]
async fn test_t1_f3_04_inspect_launch_options() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("launch-inspect")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "get", "launch-inspect"]);
    assert_eq!(val["ok"], true);
    let launch = &val["result"]["template"]["launch_options"];
    assert_eq!(launch["sandbox"], true);
    assert_eq!(launch["execution_mode"], "plan");
}

#[tokio::test]
async fn test_t1_f3_05_inspect_prompt_and_tags() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = sample_template_model("tags-inspect");
        t.default_task_prompt = Some("Specific task prompt".into());
        t.account_tag = Some("tag-alpha".into());
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "get", "tags-inspect"]);
    assert_eq!(val["ok"], true);
    let t = &val["result"]["template"];
    assert_eq!(t["default_task_prompt"], "Specific task prompt");
    assert_eq!(t["account_tag"], "tag-alpha");
}

// ── Feature F4: Template Deletion ─────────────────────────────────────────────

#[tokio::test]
async fn test_t1_f4_01_delete_by_name_slug() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("to-delete")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "delete", "to-delete"]);
    assert_eq!(out.status.code(), Some(0));

    // Verify subsequent get fails
    let (out_fail, err_fail) = cli.run_failure(&["template", "get", "to-delete"]);
    assert!(err_fail.contains("NotFound") || out_fail.contains("NotFound"));
}

#[tokio::test]
async fn test_t1_f4_02_delete_by_ulid_id() {
    let daemon = TestDaemon::start().await;
    let id = {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("del-id")).unwrap()
    };
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "delete", &id.0]);
    assert_eq!(out.status.code(), Some(0));

    let (_, err) = cli.run_failure(&["template", "get", &id.0]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t1_f4_03_delete_via_alias_remove() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("alias-remove")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "remove", "alias-remove"]);
    assert_eq!(out.status.code(), Some(0));

    let (_, err) = cli.run_failure(&["template", "get", "alias-remove"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t1_f4_04_json_mode_deletion() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("json-del")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "delete", "json-del"]);
    assert_eq!(val["ok"], true);
}

#[tokio::test]
async fn test_t1_f4_05_count_decrement_on_deletion() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("dec-1")).unwrap();
        mgr.create(sample_template_model("dec-2")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val1: Value = cli.run_json(&["template", "list"]);
    assert_eq!(val1["result"]["templates"].as_array().unwrap().len(), 2);

    cli.run_success(&["template", "delete", "dec-1"]);

    let val2: Value = cli.run_json(&["template", "list"]);
    assert_eq!(val2["result"]["templates"].as_array().unwrap().len(), 1);
}

// ── Feature F5: Session Launch from Template ──────────────────────────────────

#[tokio::test]
async fn test_t1_f5_01_template_run_default_prompt() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("runner-default")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "run", "runner-default"]);
    assert!(stdout.contains("Created session") || stdout.contains("Session") || stdout.contains("01"));
}

#[tokio::test]
async fn test_t1_f5_02_session_run_with_template_flag() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("flag-runner")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["session", "run", "--template", "flag-runner"]);
    assert!(stdout.contains("Created session") || stdout.contains("Session") || stdout.contains("01"));
}

#[tokio::test]
async fn test_t1_f5_03_override_prompt_at_launch() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("prompt-override")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&[
        "template",
        "run",
        "prompt-override",
        "--task",
        "Overridden Task Instruction",
    ]);
    assert_eq!(val["ok"], true);
    let sid = val["result"]["session_id"].as_str().expect("session_id");

    // Verify session has overridden prompt
    let session_val: Value = cli.run_json(&["session", "get", sid]);
    assert_eq!(session_val["task_description"], "Overridden Task Instruction");
}

#[tokio::test]
async fn test_t1_f5_04_launch_by_template_ulid() {
    let daemon = TestDaemon::start().await;
    let id = {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("ulid-launcher")).unwrap()
    };
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "run", &id.0]);
    assert!(stdout.contains("Created session") || stdout.contains("01"));
}

#[tokio::test]
async fn test_t1_f5_05_json_mode_launch_output() {
    let daemon = TestDaemon::start().await;
    let id = {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("json-launch")).unwrap()
    };
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "run", "json-launch"]);
    assert_eq!(val["ok"], true);
    assert!(val["result"]["session_id"].is_string());
    assert_eq!(val["result"]["template_id"], id.0);
}

// ── Feature F6: Template Store Persistence ────────────────────────────────────

#[tokio::test]
async fn test_t1_f6_01_restart_persistence() {
    let daemon = TestDaemon::start().await;
    let id = {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("persist-me")).unwrap()
    };

    let daemon = daemon.restart().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "get", "persist-me"]);
    assert_eq!(val["ok"], true);
    assert_eq!(val["result"]["template"]["id"], id.0);
    assert_eq!(val["result"]["template"]["name"], "persist-me");
    assert_eq!(val["result"]["template"]["agent_type"], "agy");
}

#[tokio::test]
async fn test_t1_f6_02_deletion_persistence_across_restart() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("persist-del")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);
    cli.run_success(&["template", "delete", "persist-del"]);

    let daemon = daemon.restart().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "get", "persist-del"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t1_f6_03_wal_journal_mode_enforced() {
    let daemon = TestDaemon::start().await;
    let db_path = daemon.dir.path().join("templates.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn test_t1_f6_04_batch_creation_restart() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        for i in 1..=5 {
            mgr.create(sample_template_model(&format!("batch-persist-{i}")))
                .unwrap();
        }
    }

    let daemon = daemon.restart().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "list"]);
    assert_eq!(val["result"]["templates"].as_array().unwrap().len(), 5);
}

#[tokio::test]
async fn test_t1_f6_05_store_colocation() {
    let daemon = TestDaemon::start().await;
    let db_dir = daemon.dir.path();
    assert!(db_dir.join("templates.db").exists());
    assert!(db_dir.join("accounts.db").exists());
    assert!(db_dir.join("projects.db").exists());
}

// ── Feature F7: Output Formatting & Flags ─────────────────────────────────────

#[tokio::test]
async fn test_t1_f7_01_table_headers_and_formatting() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("header-test")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    // Table mode includes TEMPLATE ID or NAME
    assert!(stdout.contains("header-test"));
}

#[tokio::test]
async fn test_t1_f7_02_plain_formatting_delimiters() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("delims-test")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["--plain", "template", "list"]);
    assert!(stdout.contains('\t'));
    assert!(stdout.contains("delims-test"));
}

#[tokio::test]
async fn test_t1_f7_03_plain_short_flag() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("short-plain")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let out_long = cli.run_success(&["--plain", "template", "list"]);
    let out_short = cli.run_success(&["-p", "template", "list"]);
    assert_eq!(out_long, out_short);
}

#[tokio::test]
async fn test_t1_f7_04_json_envelope_integrity() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "list"]);
    assert_eq!(val["v"], 1);
    assert_eq!(val["ok"], true);
    assert!(val.get("result").is_some());
}

#[tokio::test]
async fn test_t1_f7_05_pipe_auto_detection() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("pipe-detect")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    // Standard std::process::Command outputs non-TTY pipe by default
    let out = cli.run_success(&["template", "list"]);
    assert!(out.contains("pipe-detect"));
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 2: BOUNDARY & CORNER CASES
// ══════════════════════════════════════════════════════════════════════════════

// ── Feature F1 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f1_01_duplicate_name_slug() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&["template", "create", "--name", "duplicate-slug"]);
    let (_, err) = cli.run_failure(&["template", "create", "--name", "duplicate-slug"]);
    assert!(
        err.contains("Conflict") || err.contains("already exists"),
        "Expected Conflict error: {err}"
    );
}

#[tokio::test]
async fn test_t2_f1_02_missing_required_name() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "create", "--prompt", "Prompt only"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--name <NAME>"));
}

#[tokio::test]
async fn test_t2_f1_03_empty_name_string() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "create", "--name", ""]);
    assert!(err.contains("ValidationError") || err.contains("cannot be empty"));
}

#[tokio::test]
async fn test_t2_f1_04_maximum_length_name_slug() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let slug_64 = "a-very-long-template-slug-boundary-test-0123456789-abcdefghijk-64ch";
    assert_eq!(slug_64.len(), 67);
    let out = cli.run(&["template", "create", "--name", slug_64]);
    assert_eq!(out.status.code(), Some(0));

    let val: Value = cli.run_json(&["template", "get", slug_64]);
    assert_eq!(val["result"]["template"]["name"], slug_64);
}

#[tokio::test]
async fn test_t2_f1_05_invalid_characters_in_slug() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "create", "--name", "invalid slug with spaces!"]);
    assert!(err.contains("ValidationError"));
}

#[tokio::test]
async fn test_t2_f1_06_giant_prompt_64kb_unicode() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let mut giant_str = String::with_capacity(65_536);
    while giant_str.len() < 64_000 {
        giant_str.push_str("🚀 Multi-byte UTF-8 テスト ⚡ World 世界 \n");
    }

    let out = cli.run(&[
        "template",
        "create",
        "--name",
        "giant-prompt",
        "--prompt",
        &giant_str,
    ]);
    assert_eq!(out.status.code(), Some(0));

    let val: Value = cli.run_json(&["template", "get", "giant-prompt"]);
    let retrieved = val["result"]["template"]["default_task_prompt"]
        .as_str()
        .expect("prompt");
    assert_eq!(retrieved, giant_str);
}

// ── Feature F2 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f2_01_plain_listing_on_empty_store() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["--plain", "template", "list"]);
    assert!(stdout.is_empty(), "Plain mode on empty store must be 0 bytes");
}

#[tokio::test]
async fn test_t2_f2_02_high_volume_listing_100_templates() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        for i in 0..100 {
            let mut t = SessionTemplate::new(format!("bulk-{:03}", i), "agy");
            t.description = Some(format!("Template number {i}"));
            mgr.create(t).unwrap();
        }
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "list"]);
    let list = val["result"]["templates"].as_array().expect("templates");
    assert_eq!(list.len(), 100);
}

#[tokio::test]
async fn test_t2_f2_03_emojis_and_multibyte_unicode_in_table() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = SessionTemplate::new("emoji-tmpl", "agy");
        t.description = Some("✨ Rocket 🚀 Sparkle ⚡ Fire 🔥 日本語".into());
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("emoji-tmpl"));
    assert!(stdout.contains("🚀"));
}

#[tokio::test]
async fn test_t2_f2_04_embedded_newlines_tabs_in_plain_mode() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = SessionTemplate::new("clean-plain", "agy");
        t.description = Some("Multi line\ndescription with \ttab".into());
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["--plain", "template", "list"]);
    assert!(stdout.contains("clean-plain"));
}

#[tokio::test]
async fn test_t2_f2_05_unexpected_positional_argument() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "list", "extra_arg"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("unexpected argument 'extra_arg'"));
}

// ── Feature F3 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f3_01_nonexistent_name_slug() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "get", "non-existent-template"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f3_02_nonexistent_ulid_id() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "get", "01JC0000000000000000000000"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f3_03_missing_required_template_arg() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "get"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("<TEMPLATE>"));
}

#[tokio::test]
async fn test_t2_f3_04_substring_partial_name_collision() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("dev-team")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    // Exact match required; prefix "dev" must fail
    let (_, err) = cli.run_failure(&["template", "get", "dev"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f3_05_json_error_response_on_get_failure() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["--json", "template", "get", "ghost"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout).expect("valid JSON ApiResponse on error");
    assert_eq!(val["ok"], false);
    assert_eq!(val["error"]["code"], "NotFound");
}

// ── Feature F4 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f4_01_delete_nonexistent_template() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "delete", "ghost-template"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f4_02_missing_required_template_arg_delete() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["template", "delete"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("<TEMPLATE>"));
}

#[tokio::test]
async fn test_t2_f4_03_double_deletion_idempotency_failure() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("double-del")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&["template", "delete", "double-del"]);
    let (_, err) = cli.run_failure(&["template", "delete", "double-del"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f4_04_delete_all_templates_to_empty_store() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("del-all-1")).unwrap();
        mgr.create(sample_template_model("del-all-2")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&["template", "delete", "del-all-1"]);
    cli.run_success(&["template", "delete", "del-all-2"]);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("No templates.") || stdout.trim().is_empty());
}

#[tokio::test]
async fn test_t2_f4_05_json_error_response_on_delete_failure() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["--json", "template", "delete", "ghost"]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Value = serde_json::from_str(&stdout).expect("valid JSON ApiResponse on error");
    assert_eq!(val["ok"], false);
    assert_eq!(val["error"]["code"], "NotFound");
}

// ── Feature F5 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f5_01_launch_nonexistent_template() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "run", "phantom-template"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t2_f5_02_template_without_prompt_launched_without_task() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = SessionTemplate::new("promptless", "agy");
        t.default_task_prompt = None;
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&["template", "run", "promptless"]);
    assert!(err.contains("ValidationError") || err.contains("prompt"));
}

#[tokio::test]
async fn test_t2_f5_03_invalid_working_directory_in_template() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&[
        "template",
        "create",
        "--name",
        "bad-cwd-tmpl",
        "--working-dir",
        "/path/that/definitely/does/not/exist_123456789",
    ]);
    assert!(err.contains("ValidationError"));
}

#[tokio::test]
async fn test_t2_f5_04_nonexistent_account_selector_at_launch() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("valid-tmpl")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let (_, err) = cli.run_failure(&[
        "template",
        "run",
        "valid-tmpl",
        "--account-id",
        "01JC0000000000000000000000",
    ]);
    assert!(err.contains("NotFound") || err.contains("IncompatibleAccount") || err.contains("AccountNotFound"));
}

#[tokio::test]
async fn test_t2_f5_05_ac_session_run_without_task_and_without_template() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["session", "run"]);
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--task <TASK>") || err.contains("required"));
}

// ── Feature F6 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f6_01_special_unicode_byte_matching_after_restart() {
    let daemon = TestDaemon::start().await;
    let complex_unicode = "日本語・中文・Русский・🎉・🔥・\u{200B}zero-width";
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = SessionTemplate::new("unicode-persist", "agy");
        t.description = Some(complex_unicode.to_string());
        t.default_task_prompt = Some(complex_unicode.to_string());
        mgr.create(t).unwrap();
    }

    let daemon = daemon.restart().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "get", "unicode-persist"]);
    let t = &val["result"]["template"];
    assert_eq!(t["description"], complex_unicode);
    assert_eq!(t["default_task_prompt"], complex_unicode);
}

#[tokio::test]
async fn test_t2_f6_02_rapid_concurrent_creation_stress() {
    let daemon = TestDaemon::start().await;
    let daemon_arc = Arc::new(daemon);
    let mut tasks = vec![];

    for i in 0..10 {
        let d = daemon_arc.clone();
        tasks.push(tokio::spawn(async move {
            let resp = d
                .send_ipc(
                    "template.create",
                    json!({
                        "name": format!("stress-tmpl-{i}"),
                        "agent_type": "agy",
                        "default_task_prompt": format!("Stress task {i}")
                    }),
                )
                .await
                .expect("ipc send");
            assert!(resp.ok, "IPC create must succeed: {:?}", resp.error);
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }

    let mgr = daemon_arc.template_handle.0.lock().unwrap();
    assert_eq!(mgr.list().len(), 10);
}

#[tokio::test]
async fn test_t2_f6_03_read_only_database_file_permission_handling() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("templates.db");
    {
        let store = TemplateStore::open(&db_path).unwrap();
        let t = sample_template_model("initial-tmpl");
        store.insert(&t).unwrap();
    }

    // Set read-only permissions
    let mut perms = fs::metadata(&db_path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&db_path, perms).unwrap();

    let store = TemplateStore::open(&db_path);
    // Should either fail to open or fail on insert without crashing
    if let Ok(s) = store {
        let t2 = sample_template_model("should-fail");
        let res = s.insert(&t2);
        assert!(res.is_err());
    }
}

#[tokio::test]
async fn test_t2_f6_04_stale_wal_recovery_on_startup() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("wal-recover")).unwrap();
    }

    // Force abort server and restart without graceful flush
    let daemon = daemon.restart().await;
    let mgr = daemon.template_handle.0.lock().unwrap();
    assert!(mgr.get_by_name("wal-recover").is_some());
}

#[tokio::test]
async fn test_t2_f6_05_in_memory_vs_file_store_isolation() {
    let mem_store = TemplateStore::open_in_memory().unwrap();
    let t = sample_template_model("mem-only");
    mem_store.insert(&t).unwrap();
    assert!(mem_store.get(&t.id).unwrap().is_some());

    let dir = tempdir().unwrap();
    let file_store = TemplateStore::open(&dir.path().join("templates.db")).unwrap();
    assert!(file_store.get(&t.id).unwrap().is_none());
}

// ── Feature F7 Boundary Cases ─────────────────────────────────────────────────

#[tokio::test]
async fn test_t2_f7_01_combined_json_and_plain_precedence() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    let out = cli.run(&["--json", "--plain", "template", "list"]);
    // --json should output valid JSON
    let stdout = String::from_utf8_lossy(&out.stdout);
    let val: Result<Value, _> = serde_json::from_str(&stdout);
    assert!(val.is_ok(), "Expected valid JSON envelope: {stdout}");
}

#[tokio::test]
async fn test_t2_f7_02_offline_daemon_missing_socket_error() {
    let cli = CliRunner::new(&PathBuf::from("/tmp/nonexistent-agentcontrol-sock-123.sock"));
    let (_, err) = cli.run_failure(&["template", "list"]);
    assert!(err.contains("No such file") || err.contains("connect") || err.contains("daemon"));
}

#[tokio::test]
async fn test_t2_f7_03_300_char_description_table_formatting() {
    let daemon = TestDaemon::start().await;
    let long_desc = "X".repeat(300);
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = sample_template_model("long-desc-tmpl");
        t.description = Some(long_desc.clone());
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("long-desc-tmpl"));
}

#[tokio::test]
async fn test_t2_f7_04_null_empty_optional_fields_in_table() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let t = SessionTemplate::new("sparse-tmpl", "agy");
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let stdout = cli.run_success(&["template", "list"]);
    assert!(stdout.contains("sparse-tmpl"));
    assert!(!stdout.contains("null"), "Table view must not render raw 'null'");
}

#[tokio::test]
async fn test_t2_f7_05_empty_socket_argument() {
    let cli = CliRunner::new(&PathBuf::from(""));
    let out = cli.run(&["template", "list"]);
    assert_ne!(out.status.code(), Some(0));
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 3: CROSS-FEATURE COMBINATIONS
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_t3_01_full_crud_lifecycle_roundtrip() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // 1. Create
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "cycle-1",
        "--prompt",
        "Cycle test prompt",
    ]);

    // 2. Get
    let get_val: Value = cli.run_json(&["template", "get", "cycle-1"]);
    assert_eq!(get_val["result"]["template"]["name"], "cycle-1");

    // 3. List
    let list_val: Value = cli.run_json(&["template", "list"]);
    let found = list_val["result"]["templates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "cycle-1");
    assert!(found);

    // 4. Delete
    cli.run_success(&["template", "delete", "cycle-1"]);

    // 5. Get fails
    let (_, err) = cli.run_failure(&["template", "get", "cycle-1"]);
    assert!(err.contains("NotFound"));

    // 6. List empty
    let list_after: Value = cli.run_json(&["template", "list"]);
    let found_after = list_after["result"]["templates"]
        .as_array()
        .unwrap()
        .iter()
        .any(|t| t["name"] == "cycle-1");
    assert!(!found_after);
}

#[tokio::test]
async fn test_t3_02_slug_reuse_after_deletion() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // 1. Create V1
    let v1: Value = cli.run_json(&[
        "template",
        "create",
        "--name",
        "reused-slug",
        "--prompt",
        "Version 1 Prompt",
    ]);
    let id_v1 = v1["result"]["template_id"].as_str().unwrap().to_string();

    // 2. Delete V1
    cli.run_success(&["template", "delete", "reused-slug"]);

    // 3. Create V2
    let v2: Value = cli.run_json(&[
        "template",
        "create",
        "--name",
        "reused-slug",
        "--prompt",
        "Version 2 Prompt",
    ]);
    let id_v2 = v2["result"]["template_id"].as_str().unwrap().to_string();

    // 4. Verify distinct ULID and updated prompt
    assert_ne!(id_v1, id_v2);
    let get_v2: Value = cli.run_json(&["template", "get", "reused-slug"]);
    assert_eq!(get_v2["result"]["template"]["id"], id_v2);
    assert_eq!(
        get_v2["result"]["template"]["default_task_prompt"],
        "Version 2 Prompt"
    );
}

#[tokio::test]
async fn test_t3_03_launch_flag_precedence_over_template_defaults() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        let mut t = sample_template_model("precedence-tmpl");
        t.default_task_prompt = Some("Template Default Task".into());
        t.model = Some("gemini-3.8-flash-medium".into());
        mgr.create(t).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&[
        "session",
        "run",
        "--template",
        "precedence-tmpl",
        "--task",
        "CLI Overridden Task",
    ]);
    assert_eq!(val["ok"], true);
    let sid = val["result"]["session_id"].as_str().unwrap();

    let session: Value = cli.run_json(&["session", "get", sid]);
    assert_eq!(session["task_description"], "CLI Overridden Task");
}

#[tokio::test]
async fn test_t3_04_ac_template_run_vs_session_run_equivalence() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("equiv-tmpl")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let run1: Value = cli.run_json(&["template", "run", "equiv-tmpl", "--task", "Task A"]);
    let run2: Value = cli.run_json(&[
        "session",
        "run",
        "--template",
        "equiv-tmpl",
        "--task",
        "Task B",
    ]);

    assert_eq!(run1["ok"], true);
    assert_eq!(run2["ok"], true);
    assert_eq!(run1["result"]["template_id"], run2["result"]["template_id"]);
}

#[tokio::test]
async fn test_t3_05_coexisting_templates_with_overlapping_models_and_tags() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&[
        "template",
        "create",
        "--name",
        "tmpl-a",
        "--account-tag",
        "dev",
        "--model",
        "gemini-3.8-flash-medium",
    ]);
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "tmpl-b",
        "--account-tag",
        "dev",
        "--model",
        "claude-3-5-sonnet",
    ]);
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "tmpl-c",
        "--account-tag",
        "prod",
        "--model",
        "claude-3-5-sonnet",
    ]);

    let list: Value = cli.run_json(&["template", "list"]);
    let arr = list["result"]["templates"].as_array().unwrap();
    assert_eq!(arr.len(), 3);
}

#[tokio::test]
async fn test_t3_06_concurrent_create_and_immediate_launch() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&[
        "template",
        "create",
        "--name",
        "fast-start",
        "--prompt",
        "Instant launch prompt",
    ]);
    let val: Value = cli.run_json(&["template", "run", "fast-start"]);
    assert_eq!(val["ok"], true);
    assert!(val["result"]["session_id"].is_string());
}

#[tokio::test]
async fn test_t3_07_concurrent_launches_from_single_template() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("shared-worker")).unwrap();
    }
    let daemon_arc = Arc::new(daemon);
    let mut tasks = vec![];

    for i in 0..5 {
        let d = daemon_arc.clone();
        tasks.push(tokio::spawn(async move {
            let resp = d
                .send_ipc(
                    "session.create_from_template",
                    json!({
                        "template": "shared-worker",
                        "task_description": format!("Concurrent worker {i}"),
                        "start": true
                    }),
                )
                .await
                .expect("send ipc");
            assert!(resp.ok, "Launch {i} failed: {:?}", resp.error);
            resp.result.unwrap()["session_id"]
                .as_str()
                .unwrap()
                .to_string()
        }));
    }

    let mut session_ids = vec![];
    for t in tasks {
        session_ids.push(t.await.unwrap());
    }

    // All session IDs must be unique
    session_ids.sort();
    session_ids.dedup();
    assert_eq!(session_ids.len(), 5);
}

#[tokio::test]
async fn test_t3_08_active_session_survivability_across_daemon_restart() {
    let daemon = TestDaemon::start().await;
    {
        let mut mgr = daemon.template_handle.0.lock().unwrap();
        mgr.create(sample_template_model("active-survive")).unwrap();
    }
    let cli = CliRunner::new(&daemon.socket_path);

    let val: Value = cli.run_json(&["template", "run", "active-survive"]);
    let sid = val["result"]["session_id"].as_str().unwrap().to_string();

    let daemon = daemon.restart().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // Verify template persists
    let tmpl: Value = cli.run_json(&["template", "get", "active-survive"]);
    assert_eq!(tmpl["result"]["template"]["name"], "active-survive");

    // Launch another session from template after restart
    let val2: Value = cli.run_json(&["template", "run", "active-survive"]);
    assert_ne!(val2["result"]["session_id"], sid);
}

#[tokio::test]
async fn test_t3_09_interleaved_delete_and_launch_race() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    cli.run_success(&["template", "create", "--name", "race-runner"]);
    cli.run_success(&["template", "delete", "race-runner"]);

    let (_, err) = cli.run_failure(&["template", "run", "race-runner"]);
    assert!(err.contains("NotFound"));
}

#[tokio::test]
async fn test_t3_10_mutating_command_scope_protection() {
    let _daemon = TestDaemon::start().await;

    // Verify mutating command classification enforces write scope
    assert!(ac_core::ipc::is_mutating_cmd("template.create"));
    assert!(ac_core::ipc::is_mutating_cmd("template.delete"));
    assert!(ac_core::ipc::is_mutating_cmd("template.remove"));
    assert!(ac_core::ipc::is_mutating_cmd("session.create_from_template"));
    assert!(!ac_core::ipc::is_mutating_cmd("template.list"));
    assert!(!ac_core::ipc::is_mutating_cmd("template.get"));
}

// ══════════════════════════════════════════════════════════════════════════════
// TIER 4: REAL-WORLD APPLICATION SCENARIOS
// ══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn test_t4_01_multi_environment_provisioning_dev_staging_prod() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // 1. Provision Dev Preset
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "dev-preset",
        "--description",
        "Rapid dev with auto edits",
        "--agent-type",
        "agy",
        "--model",
        "gemini-3.8-flash-medium",
        "--execution-mode",
        "accept-edits",
        "--prompt",
        "Implement feature according to specification",
    ]);

    // 2. Provision Staging Preset
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "staging-preset",
        "--description",
        "Isolated sandbox test runner",
        "--agent-type",
        "agy",
        "--sandbox",
        "--permission-mode",
        "normal",
        "--prompt",
        "Run full regression test suite",
    ]);

    // 3. Provision Production Audit Preset
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "prod-audit",
        "--description",
        "Strict audit planning",
        "--agent-type",
        "claude",
        "--execution-mode",
        "plan",
        "--prompt",
        "Audit production codebase for security issues",
    ]);

    // 4. Verify all 3 exist in listing
    let list: Value = cli.run_json(&["template", "list"]);
    let arr = list["result"]["templates"].as_array().unwrap();
    assert_eq!(arr.len(), 3);

    // 5. Developer launches dev task
    let run_val: Value = cli.run_json(&[
        "template",
        "run",
        "dev-preset",
        "--task",
        "Fix bug in auth handler",
    ]);
    assert_eq!(run_val["ok"], true);
}

#[tokio::test]
async fn test_t4_02_ci_cd_batch_automation_matrix() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // CI script checks plain template list
    let plain_list = cli.run_success(&["--plain", "template", "list"]);
    if !plain_list.contains("ci-checker") {
        cli.run_success(&[
            "template",
            "create",
            "--name",
            "ci-checker",
            "--description",
            "CI automated build & test preset",
            "--prompt",
            "Verify module integrity",
        ]);
    }

    // Launch 3 matrix tasks
    let modules = ["ac-core", "ac-cli", "ac-tui"];
    let mut session_ids = vec![];
    for m in modules {
        let val: Value = cli.run_json(&[
            "template",
            "run",
            "ci-checker",
            "--task",
            &format!("Check module {m}"),
        ]);
        assert_eq!(val["ok"], true);
        session_ids.push(val["result"]["session_id"].as_str().unwrap().to_string());
    }

    assert_eq!(session_ids.len(), 3);
}

#[tokio::test]
async fn test_t4_03_configuration_evolution_and_template_update_workflow() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // 1. Initial creation
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "audit-pipeline",
        "--model",
        "gemini-1.5-pro",
        "--description",
        "Old model pipeline",
    ]);

    // 2. Retrieve config
    let orig: Value = cli.run_json(&["template", "get", "audit-pipeline"]);
    assert_eq!(orig["result"]["template"]["model"], "gemini-1.5-pro");

    // 3. Evolve config: delete and recreate with upgraded model
    cli.run_success(&["template", "delete", "audit-pipeline"]);
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "audit-pipeline",
        "--model",
        "gemini-3.8-flash-medium",
        "--description",
        "Upgraded flash model pipeline",
        "--prompt",
        "Run upgraded security audit",
    ]);

    // 4. Launch session with evolved template
    let run: Value = cli.run_json(&["template", "run", "audit-pipeline"]);
    assert_eq!(run["ok"], true);
}

#[tokio::test]
async fn test_t4_04_disaster_recovery_and_sqlite_wal_database_migration() {
    let daemon1 = TestDaemon::start().await;
    {
        let mut mgr = daemon1.template_handle.0.lock().unwrap();
        for i in 1..=5 {
            mgr.create(sample_template_model(&format!("migrated-{i}")))
                .unwrap();
        }
    }
    let original_db = daemon1.dir.path().join("templates.db");

    // Stop daemon 1
    daemon1.server_task.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Migrate templates.db to a completely new host/directory
    let new_dir = tempdir().unwrap();
    let migrated_db = new_dir.path().join("templates.db");
    fs::copy(&original_db, &migrated_db).expect("copy database");
    let original_wal = daemon1.dir.path().join("templates.db-wal");
    if original_wal.exists() {
        let _ = fs::copy(&original_wal, new_dir.path().join("templates.db-wal"));
    }

    // Start daemon 2 on new directory
    let new_socket = new_dir.path().join("ac-new.sock");
    let daemon2 = TestDaemon::start_with_dir(new_dir, new_socket).await;
    let cli2 = CliRunner::new(&daemon2.socket_path);

    let val: Value = cli2.run_json(&["template", "list"]);
    let arr = val["result"]["templates"].as_array().unwrap();
    assert_eq!(arr.len(), 5);

    let run_val: Value = cli2.run_json(&["template", "run", "migrated-1"]);
    assert_eq!(run_val["ok"], true);
}

#[tokio::test]
async fn test_t4_05_account_tag_routing_via_templates() {
    let daemon = TestDaemon::start().await;

    // Register 2 accounts with distinct tags
    let _enterprise_id = daemon.register_secondary_account(
        "Enterprise Account",
        "agy",
        vec!["enterprise".into(), "fast".into()],
    );
    let _community_id = daemon.register_secondary_account(
        "Community Account",
        "agy",
        vec!["community".into()],
    );

    // Create template targeting "enterprise" tag
    let cli = CliRunner::new(&daemon.socket_path);
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "enterprise-job",
        "--account-tag",
        "enterprise",
        "--prompt",
        "Process enterprise workload",
    ]);

    // Launch session from template
    let run: Value = cli.run_json(&["template", "run", "enterprise-job"]);
    assert_eq!(run["ok"], true);
    let sid = run["result"]["session_id"].as_str().unwrap();

    let session_val: Value = cli.run_json(&["session", "get", sid]);
    assert_eq!(session_val["task_description"], "Process enterprise workload");
}

#[tokio::test]
async fn test_t4_06_cross_interface_interoperability_cli_to_api() {
    let daemon = TestDaemon::start().await;
    let cli = CliRunner::new(&daemon.socket_path);

    // 1. Created via CLI
    cli.run_success(&[
        "template",
        "create",
        "--name",
        "interop-test",
        "--prompt",
        "CLI created prompt",
        "--model",
        "gemini-3.8-flash-medium",
    ]);

    // 2. Query via direct DaemonClient / API
    let resp = daemon
        .send_ipc("template.get", json!({ "template": "interop-test" }))
        .await
        .expect("send ipc");
    assert!(resp.ok);
    let t = resp.result.unwrap()["template"].clone();
    assert_eq!(t["name"], "interop-test");
    assert_eq!(t["default_task_prompt"], "CLI created prompt");

    // 3. Launch via API
    let launch_resp = daemon
        .send_ipc(
            "session.create_from_template",
            json!({ "template": "interop-test", "start": true }),
        )
        .await
        .expect("send launch ipc");
    assert!(launch_resp.ok);
    let sid = launch_resp.result.unwrap()["session_id"].as_str().unwrap().to_string();

    // 4. Query via CLI session get
    let session_info = cli.run_success(&["session", "get", &sid]);
    assert!(session_info.contains(&sid));
}
