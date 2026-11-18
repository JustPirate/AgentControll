//! Comprehensive integration test suite for Feature F5 / ADR-008:
//! Dynamic Subprocess Adapter Plugins.
//!
//! Validates:
//! 1. `test_plugin_config_deserialization_and_validation`: TOML deserialization,
//!    capabilities conversion, and validation rejection of empty name/executable/agent_types,
//!    duplicate plugin names, and conflicting agent_types.
//! 2. `test_composite_adapter_factory_plugin_routing`: Plugin registration, capabilities
//!    routing, preflight checks, and unknown agent type fallback.
//! 3. `test_subprocess_adapter_lifecycle_normal`: Normal lifecycle with NDJSON ready,
//!    output, and completed events.
//! 4. `test_subprocess_adapter_interactive_prompts_and_commands`: Interactive approval/prompt
//!    handling and daemon respond commands over stdin.
//! 5. `test_subprocess_adapter_plaintext_fallback`: Plaintext output lines falling back
//!    to low-confidence output chunks.
//! 6. `test_subprocess_adapter_graceful_stop`: Graceful stop command handling and process termination.
//! 7. `test_subprocess_adapter_drop_guard_cleanup`: RAII drop guard killing long-running
//!    child process with SIGKILL.
//! 8. `test_subprocess_adapter_crash_with_stderr_capture`: Crash detection on non-zero exit code
//!    with stderr buffer capture in the crashed event reason.
//! 9. `test_subprocess_adapter_environment_and_workspace_isolation`: Neutralized D-Bus keyring,
//!    ambient auth env stripping, injected context/plugin env, and workspace directory boundary.
//! 10. Adversarial verification: special characters, escaping integrity, and preflight failures.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use ac_core::adapter::plugin::{parse_plugin_event, SubprocessAdapter};
use ac_core::adapter::{AdapterFactory, CompositeAdapterFactory};
use ac_core::config::{Config, PluginCapabilitiesConfig, PluginConfig};
use ac_core::types::{
    AccountSwitchMode, AdapterEvent, AgentCommand, Confidence, Id, ProviderCapabilities,
    SessionContext,
};
use tempfile::tempdir;
use tokio::sync::mpsc;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to create an executable mock script in the given directory.
fn create_mock_script(dir: &Path, name: &str, content: &str) -> PathBuf {
    let script_path = dir.join(name);
    fs::write(&script_path, content).expect("failed to write mock script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&script_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script_path, perms).expect("set_permissions");
    }
    script_path
}

/// Helper to receive the next event with a timeout.
async fn recv_event(
    rx: &mut mpsc::Receiver<AdapterEvent>,
    timeout: Duration,
) -> Option<AdapterEvent> {
    tokio::time::timeout(timeout, rx.recv()).await.ok().flatten()
}

// ── 1. Configuration Deserialization & Validation ─────────────────────────────

#[test]
fn test_plugin_config_deserialization_and_validation() {
    let toml_str = r#"
        socket_path = "/tmp/test.sock"
        db_path = "/tmp/test.db"

        [[plugins]]
        name = "devin-adapter"
        executable = "/usr/bin/devin"
        args = ["--mode", "daemon", "--log-format", "json"]
        agent_types = ["devin", "cognition"]

        [plugins.env]
        DEVIN_REGION = "us-west-2"
        DEVIN_TIMEOUT = "300"

        [plugins.capabilities]
        switch_mode = "dynamic"
        supports_session_resume = true
        supports_snapshot_restore = true
        requires_process_restart = false
        supports_pty = true
        supports_auto_accept = true
        models = ["devin-default", "devin-fast"]
    "#;

    // 1. Deserialization into Config
    let cfg: Config = toml::from_str(toml_str).expect("failed to deserialize config");
    assert_eq!(cfg.plugins.len(), 1);

    let plugin = &cfg.plugins[0];
    assert_eq!(plugin.name, "devin-adapter");
    assert_eq!(plugin.executable, PathBuf::from("/usr/bin/devin"));
    assert_eq!(plugin.args, vec!["--mode", "daemon", "--log-format", "json"]);
    assert_eq!(plugin.agent_types, vec!["devin", "cognition"]);
    assert_eq!(plugin.env.get("DEVIN_REGION"), Some(&"us-west-2".to_string()));
    assert_eq!(plugin.env.get("DEVIN_TIMEOUT"), Some(&"300".to_string()));

    // 2. Capabilities conversion
    assert!(plugin.capabilities.supports_pty);
    assert!(plugin.capabilities.supports_auto_accept);
    assert_eq!(
        plugin.capabilities.models,
        vec!["devin-default".to_string(), "devin-fast".to_string()]
    );

    let caps = plugin.capabilities.to_provider_capabilities();
    assert_eq!(caps.switch_mode, AccountSwitchMode::Dynamic);
    assert!(caps.supports_session_resume);
    assert!(caps.supports_snapshot_restore);
    assert!(!caps.requires_process_restart);

    let from_ref: ProviderCapabilities = (&plugin.capabilities).into();
    assert_eq!(from_ref, caps);
    let from_val: ProviderCapabilities = plugin.capabilities.clone().into();
    assert_eq!(from_val, caps);

    // 3. Validation success on valid config
    assert!(plugin.validate().is_ok());
    assert!(cfg.validate().is_ok());

    // 4. Validation failure on empty name
    let empty_name = PluginConfig::new("", "/bin/sh", vec!["devin".into()]);
    let err = empty_name.validate().unwrap_err();
    assert!(err.to_string().contains("plugin name cannot be empty"));

    let ws_name = PluginConfig::new("   ", "/bin/sh", vec!["devin".into()]);
    let err = ws_name.validate().unwrap_err();
    assert!(err.to_string().contains("plugin name cannot be empty"));

    // 5. Validation failure on empty executable
    let empty_exe = PluginConfig::new("devin", "", vec!["devin".into()]);
    let err = empty_exe.validate().unwrap_err();
    assert!(err.to_string().contains("executable cannot be empty"));

    // 6. Validation failure on empty agent_types
    let empty_types = PluginConfig::new("devin", "/bin/sh", vec![]);
    let err = empty_types.validate().unwrap_err();
    assert!(err.to_string().contains("must specify at least one agent_type"));

    // 7. Validation failure on whitespace agent_type
    let ws_type = PluginConfig::new("devin", "/bin/sh", vec!["   ".into()]);
    let err = ws_type.validate().unwrap_err();
    assert!(err.to_string().contains("contains an empty agent_type"));

    // 8. Config validation rejection of duplicate plugin names
    let mut dup_cfg = Config::default();
    dup_cfg.plugins = vec![
        PluginConfig::new("my-plugin", "/bin/sh", vec!["type-a".into()]),
        PluginConfig::new("my-plugin", "/bin/bash", vec!["type-b".into()]),
    ];
    let err = dup_cfg.validate().unwrap_err();
    assert!(err.to_string().contains("duplicate plugin name: 'my-plugin'"));

    // 9. Config validation rejection of conflicting agent_types
    let mut conflict_cfg = Config::default();
    conflict_cfg.plugins = vec![
        PluginConfig::new("plugin-1", "/bin/sh", vec!["shared-agent".into()]),
        PluginConfig::new("plugin-2", "/bin/bash", vec!["shared-agent".into()]),
    ];
    let err = conflict_cfg.validate().unwrap_err();
    assert!(
        err.to_string().contains("conflicting agent_type 'shared-agent'"),
        "error was: {}",
        err
    );
}

// ── 2. Composite Adapter Factory Routing ──────────────────────────────────────

#[test]
fn test_composite_adapter_factory_plugin_routing() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "mock_adapter.sh",
        "#!/bin/sh\necho '{\"type\":\"ready\"}'\nexit 0\n",
    );

    let plugin = PluginConfig::new(
        "custom-plugin",
        &script,
        vec!["custom-agent".into(), "custom-agent-v2".into()],
    )
    .with_capabilities(PluginCapabilitiesConfig {
        switch_mode: AccountSwitchMode::Dynamic,
        supports_session_resume: true,
        supports_snapshot_restore: true,
        requires_process_restart: false,
        supports_pty: true,
        supports_auto_accept: true,
        models: vec!["custom-m1".into()],
    });

    let mut factory = CompositeAdapterFactory::new().with_plugins(vec![plugin]);
    assert_eq!(factory.plugins.len(), 1);

    // 1. Querying capabilities for primary agent_type
    let caps1 = factory.capabilities("custom-agent");
    assert_eq!(caps1.switch_mode, AccountSwitchMode::Dynamic);
    assert!(caps1.supports_session_resume);
    assert!(caps1.supports_snapshot_restore);
    assert!(!caps1.requires_process_restart);

    // 2. Querying capabilities for alias agent_type
    let caps2 = factory.capabilities("custom-agent-v2");
    assert_eq!(caps2.switch_mode, AccountSwitchMode::Dynamic);

    // 3. Fallback for unknown agent type to generic-pty defaults
    let fallback_caps = factory.capabilities("completely-unknown-agent-xyz");
    assert_eq!(fallback_caps.switch_mode, AccountSwitchMode::RequiresRestart);
    assert!(!fallback_caps.supports_session_resume);

    // 4. Built-in routing for claude still works
    let claude_caps = factory.capabilities("claude");
    assert_eq!(claude_caps.switch_mode, AccountSwitchMode::RequiresRestart);

    // 5. Preflight check for valid plugin with valid workspace
    let ctx_valid = SessionContext::new(Id::new(), "task description".into(), "custom-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());
    assert!(factory.preflight(&ctx_valid).is_ok());

    // 6. Preflight failure when executable does not exist
    let bad_plugin = PluginConfig::new(
        "bad-plugin",
        tmp.path().join("nonexistent_binary_file"),
        vec!["bad-agent".into()],
    );
    factory.register_plugin(bad_plugin);
    assert_eq!(factory.plugins.len(), 2);

    let ctx_bad = SessionContext::new(Id::new(), "task".into(), "bad-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());
    let err = factory.preflight(&ctx_bad).unwrap_err();
    assert!(err.to_string().contains("does not exist"));

    // 7. Preflight for unknown agent type passes through fallback
    let ctx_unknown = SessionContext::new(Id::new(), "task".into(), "unknown-agent".into());
    assert!(factory.preflight(&ctx_unknown).is_ok());
}

// ── 3. Subprocess Adapter Normal Lifecycle ───────────────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_lifecycle_normal() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "lifecycle.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"output","text":"chunk 1\n"}'
printf '%s\n' '{"type":"completed","summary":"success"}'
exit 0
"#,
    );

    let plugin = PluginConfig::new("lifecycle-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "run task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Event 1: Ready
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // Event 2: OutputChunk
    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk event");
    match evt2 {
        AdapterEvent::OutputChunk { text, .. } => {
            assert_eq!(text, "chunk 1\n");
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    // Event 3: Completed
    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Completed event");
    match evt3 {
        AdapterEvent::Completed { summary } => {
            assert_eq!(summary, Some("success".to_string()));
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    drop(handle);
}

// ── 4. Subprocess Adapter Interactive Prompts & Commands ─────────────────────

#[tokio::test]
async fn test_subprocess_adapter_interactive_prompts_and_commands() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "interactive.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"approval_requested","tool_name":"bash","prompt":"run destructive command?"}'
while IFS= read -r line; do
    case "$line" in
        *'"type":"respond"'*)
            printf '{"type":"output","text":"child received response: %s\\n"}\n' "$line"
            printf '%s\n' '{"type":"completed","summary":"prompt handled successfully"}'
            exit 0
            ;;
    esac
done
"#,
    );

    let plugin = PluginConfig::new("interactive-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "interactive task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let mut handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // 1. Receive Ready
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // 2. Receive ApprovalRequested
    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected ApprovalRequested event");
    match evt2 {
        AdapterEvent::ApprovalRequested { tool_name, prompt } => {
            assert_eq!(tool_name, "bash");
            assert_eq!(prompt, "run destructive command?");
        }
        other => panic!("expected ApprovalRequested, got {:?}", other),
    }

    // 3. Daemon sends AgentCommand::Respond
    handle
        .send_command(AgentCommand::Respond {
            allow: true,
            response: Some("confirmed".into()),
        })
        .expect("failed to send respond command");

    // 4. Child receives command over stdin and emits output
    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk event");
    match evt3 {
        AdapterEvent::OutputChunk { text, .. } => {
            assert!(
                text.contains("child received response:") && text.contains("confirmed"),
                "unexpected output chunk text: {}",
                text
            );
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    // 5. Child emits completed
    let evt4 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Completed event");
    match evt4 {
        AdapterEvent::Completed { summary } => {
            assert_eq!(summary, Some("prompt handled successfully".to_string()));
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    drop(handle);
}

// ── 5. Subprocess Adapter Plaintext Fallback ──────────────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_plaintext_fallback() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "plaintext.sh",
        r#"#!/bin/sh
echo "Step 1: processing workspace files..."
echo "Step 2: all tasks complete successfully."
exit 0
"#,
    );

    let plugin = PluginConfig::new("plaintext-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "plaintext task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // First line triggers implicit Ready if not yet emitted
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // Plaintext line 1 wrapped as OutputChunk with Confidence::Low
    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk 1");
    match evt2 {
        AdapterEvent::OutputChunk { text, confidence } => {
            assert_eq!(text, "Step 1: processing workspace files...");
            assert_eq!(confidence, Confidence::Low);
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    // Plaintext line 2 wrapped as OutputChunk with Confidence::Low
    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk 2");
    match evt3 {
        AdapterEvent::OutputChunk { text, confidence } => {
            assert_eq!(text, "Step 2: all tasks complete successfully.");
            assert_eq!(confidence, Confidence::Low);
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    drop(handle);
}

// ── 6. Subprocess Adapter Graceful Stop ───────────────────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_graceful_stop() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "graceful_stop.sh",
        r#"#!/bin/sh
trap 'printf "%s\n" "{\"type\":\"output\",\"text\":\"stopping now\"}"; printf "%s\n" "{\"type\":\"completed\",\"summary\":\"stopped gracefully by signal\"}"; exit 0' TERM
printf '%s\n' '{"type":"ready"}'
while IFS= read -r line; do
    case "$line" in
        *'"type":"stop"'*)
            printf '%s\n' '{"type":"output","text":"stopping now"}'
            printf '%s\n' '{"type":"completed","summary":"stopped gracefully by command"}'
            exit 0
            ;;
    esac
done
"#,
    );

    let plugin = PluginConfig::new("stop-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "stop task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let mut handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Wait for Ready
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // Send Stop command
    handle
        .send_command(AgentCommand::Stop {
            reason: Some("graceful test shutdown".into()),
        })
        .expect("failed to send stop command");

    // Collect subsequent events until exit
    let mut received_output = false;
    let mut received_completed = false;

    for _ in 0..10 {
        if let Some(evt) = recv_event(&mut event_rx, Duration::from_secs(3)).await {
            match evt {
                AdapterEvent::OutputChunk { text, .. } if text.contains("stopping now") => {
                    received_output = true;
                }
                AdapterEvent::Completed { summary } => {
                    received_completed = true;
                    if let Some(s) = summary {
                        if s.contains("stopped gracefully") {
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    assert!(received_output, "expected 'stopping now' output chunk");
    assert!(received_completed, "expected Completed event on graceful stop");

    drop(handle);
}

// ── 7. Subprocess Adapter Drop Guard Cleanup ─────────────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_drop_guard_cleanup() {
    let tmp = tempdir().expect("tempdir");
    let pid_file = tmp.path().join("child.pid");

    let script = create_mock_script(
        tmp.path(),
        "long_running.sh",
        r#"#!/bin/sh
echo $$ > "$1"
echo '{"type":"ready"}'
while true; do
    sleep 1
done
"#,
    );

    let plugin = PluginConfig::new("drop-plugin", &script, vec!["test-agent".into()])
        .with_arg(pid_file.to_str().unwrap());

    let ctx = SessionContext::new(Id::new(), "drop task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Wait for child to become ready and write its PID
    let evt = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt, AdapterEvent::Ready));

    let pid_str = fs::read_to_string(&pid_file).expect("reading pid file");
    let child_pid: i32 = pid_str.trim().parse().expect("valid integer pid");

    // Child process is confirmed alive
    #[cfg(unix)]
    assert_eq!(
        unsafe { libc::kill(child_pid, 0) },
        0,
        "Child process {} must be running before drop",
        child_pid
    );

    // Drop the adapter handle — triggering SubprocessDropGuard::drop
    drop(handle);

    // Verify child process is killed with SIGKILL and terminated
    #[cfg(unix)]
    {
        let mut terminated = false;
        let mut status: libc::c_int = 0;

        for _ in 0..50 {
            let ret = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            if ret == child_pid {
                terminated = true;
                assert!(libc::WIFSIGNALED(status), "Process should be killed by signal");
                assert_eq!(
                    libc::WTERMSIG(status),
                    libc::SIGKILL,
                    "Expected SIGKILL termination"
                );
                break;
            } else if ret == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ECHILD)
                    || err.raw_os_error() == Some(libc::ESRCH)
                {
                    terminated = true;
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        assert!(
            terminated,
            "Child process {} was not terminated after handle drop",
            child_pid
        );

        // Process must no longer exist
        let check = unsafe { libc::kill(child_pid, 0) };
        assert_eq!(
            check, -1,
            "Child PID {} still responded to kill(pid, 0)",
            child_pid
        );
    }
}

// ── 8. Subprocess Adapter Crash with Stderr Capture ──────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_crash_with_stderr_capture() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "crash.sh",
        r#"#!/bin/sh
echo '{"type":"ready"}'
>&2 echo "CRITICAL_FAILURE: memory allocation failed in subsystem"
>&2 echo "Diagnostic: stack dump frame 0xdeadbeef"
exit 42
"#,
    );

    let plugin = PluginConfig::new("crash-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "crash task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    let mut crashed_event: Option<AdapterEvent> = None;
    for _ in 0..10 {
        if let Some(evt) = recv_event(&mut event_rx, Duration::from_secs(3)).await {
            if matches!(evt, AdapterEvent::Crashed { .. }) {
                crashed_event = Some(evt);
                break;
            }
        }
    }

    let crashed = crashed_event.expect("expected Crashed event from monitor task");
    match crashed {
        AdapterEvent::Crashed { exit_code, reason } => {
            assert_eq!(exit_code, Some(42));
            let reason_text = reason.expect("expected crash reason containing stderr");
            assert!(
                reason_text.contains("CRITICAL_FAILURE: memory allocation failed"),
                "reason did not contain first stderr line: {}",
                reason_text
            );
            assert!(
                reason_text.contains("stack dump frame 0xdeadbeef"),
                "reason did not contain second stderr line: {}",
                reason_text
            );
            assert!(
                reason_text.contains("42"),
                "reason did not contain exit status 42: {}",
                reason_text
            );
        }
        other => panic!("expected Crashed, got {:?}", other),
    }

    drop(handle);
}

// ── 9. Environment & Workspace Isolation ─────────────────────────────────────

#[tokio::test]
async fn test_subprocess_adapter_environment_and_workspace_isolation() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    // Inject ambient auth variables into current process to verify stripping
    std::env::set_var("GEMINI_API_KEY", "secret-ambient-gemini-key");
    std::env::set_var("GOOGLE_API_KEY", "secret-ambient-google-key");

    let tmp = tempdir().expect("tempdir");
    let ws_dir = tmp.path().join("workspace_root");
    fs::create_dir_all(&ws_dir).expect("create workspace_root");

    let script = create_mock_script(
        tmp.path(),
        "isolation_check.sh",
        r#"#!/bin/sh
# 1. Ambient auth env vars must be stripped
if [ -n "$GEMINI_API_KEY" ]; then
    echo "FAIL: GEMINI_API_KEY present: $GEMINI_API_KEY" >&2
    exit 11
fi
if [ -n "$GOOGLE_API_KEY" ]; then
    echo "FAIL: GOOGLE_API_KEY present: $GOOGLE_API_KEY" >&2
    exit 12
fi

# 2. Keyring isolation
if [ "$DBUS_SESSION_BUS_ADDRESS" != "disabled:" ]; then
    echo "FAIL: DBUS_SESSION_BUS_ADDRESS is '$DBUS_SESSION_BUS_ADDRESS', expected 'disabled:'" >&2
    exit 13
fi

# 3. Context environment variables
if [ "$AC_AGENT_TYPE" != "isolated-test-agent" ]; then
    echo "FAIL: AC_AGENT_TYPE is '$AC_AGENT_TYPE'" >&2
    exit 14
fi
if [ -z "$AC_SESSION_ID" ]; then
    echo "FAIL: AC_SESSION_ID is empty" >&2
    exit 15
fi
if [ -z "$AC_WORKSPACE_PATH" ]; then
    echo "FAIL: AC_WORKSPACE_PATH is empty" >&2
    exit 16
fi

# 4. Custom plugin configuration env
if [ "$MY_CUSTOM_ISOLATION_VAR" != "custom_isolation_value_xyz" ]; then
    echo "FAIL: MY_CUSTOM_ISOLATION_VAR is '$MY_CUSTOM_ISOLATION_VAR'" >&2
    exit 17
fi

# 5. Workspace working directory boundary
CURRENT_DIR=$(pwd -P)
EXPECTED_DIR=$(cd "$AC_WORKSPACE_PATH" && pwd -P)
if [ "$CURRENT_DIR" != "$EXPECTED_DIR" ]; then
    echo "FAIL: pwd '$CURRENT_DIR' != workspace '$EXPECTED_DIR'" >&2
    exit 18
fi

printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"output","text":"all-isolation-checks-passed\n"}'
printf '%s\n' '{"type":"completed","summary":"isolation verified"}'
exit 0
"#,
    );

    let plugin = PluginConfig::new("isolation-plugin", &script, vec!["isolated-test-agent".into()])
        .with_env("MY_CUSTOM_ISOLATION_VAR", "custom_isolation_value_xyz");

    let session_id = Id::new();
    let ctx = SessionContext::new(
        session_id,
        "isolation check task".into(),
        "isolated-test-agent".into(),
    )
    .with_workspace(ws_dir.to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Verify Ready
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // Verify OutputChunk confirming all isolation checks passed
    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk event");
    match evt2 {
        AdapterEvent::OutputChunk { text, .. } => {
            assert!(
                text.contains("all-isolation-checks-passed"),
                "unexpected chunk: {}",
                text
            );
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    // Verify Completed
    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Completed event");
    assert!(matches!(evt3, AdapterEvent::Completed { .. }));

    // Clean up ambient env in parent
    std::env::remove_var("GEMINI_API_KEY");
    std::env::remove_var("GOOGLE_API_KEY");

    drop(handle);
}

// ── 10. Adversarial Verification: Special Characters & Escaping ───────────────

#[tokio::test]
async fn test_subprocess_adapter_special_characters_and_escaping() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "escaping.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"output","text":"Unicode test: \u2714 \u2716 \ud83d\ude80 \nTabs:\t quotes: \"hello\" \r\n"}'
printf '%s\n' '{"type":"approval_requested","tool_name":"curl","prompt":"URL with meta-chars: https://api.example.com?q=a%20b&key=123#frag"}'
printf '%s\n' '{"type":"completed","summary":"Finished with 100% precision: <tag> & \"entities\""}'
exit 0
"#,
    );

    let plugin = PluginConfig::new("escape-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "escape task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Ready
    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    // OutputChunk with unicode & escaped quotes
    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("OutputChunk event");
    match evt2 {
        AdapterEvent::OutputChunk { text, .. } => {
            assert!(text.contains("Unicode test:"), "text: {}", text);
            assert!(text.contains("\"hello\""), "text: {}", text);
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    // ApprovalRequested with query params & meta-chars
    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("ApprovalRequested event");
    match evt3 {
        AdapterEvent::ApprovalRequested { tool_name, prompt } => {
            assert_eq!(tool_name, "curl");
            assert!(prompt.contains("https://api.example.com?q=a%20b&key=123#frag"));
        }
        other => panic!("expected ApprovalRequested, got {:?}", other),
    }

    // Completed with HTML/XML meta-chars
    let evt4 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("Completed event");
    match evt4 {
        AdapterEvent::Completed { summary } => {
            let s = summary.expect("summary");
            assert!(s.contains("<tag> & \"entities\""));
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    drop(handle);
}

// ── 11. Preflight Failure Edge Cases ─────────────────────────────────────────

#[test]
fn test_subprocess_adapter_preflight_failures() {
    let tmp = tempdir().expect("tempdir");

    // 1. Nonexistent executable
    let plugin_bad_exe = PluginConfig::new(
        "bad-exe",
        tmp.path().join("missing_binary"),
        vec!["agent".into()],
    );
    let ctx = SessionContext::new(Id::new(), "task".into(), "agent".into());
    let err = SubprocessAdapter::preflight(&ctx, &plugin_bad_exe).unwrap_err();
    assert!(err.to_string().contains("does not exist"));

    // 2. Nonexistent workspace path
    let script = create_mock_script(tmp.path(), "ok.sh", "#!/bin/sh\nexit 0\n");
    let plugin_ok = PluginConfig::new("ok", &script, vec!["agent".into()]);
    let ctx_bad_ws = SessionContext::new(Id::new(), "task".into(), "agent".into())
        .with_workspace(tmp.path().join("missing_directory").to_str().unwrap());
    let err = SubprocessAdapter::preflight(&ctx_bad_ws, &plugin_ok).unwrap_err();
    assert!(err.to_string().contains("Workspace directory does not exist"));

    // 3. File exists but permissions lack execute bit
    let non_exec_file = tmp.path().join("not_executable.txt");
    fs::write(&non_exec_file, "plain text").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&non_exec_file).unwrap().permissions();
        perms.set_mode(0o644); // no exec bit
        fs::set_permissions(&non_exec_file, perms).unwrap();
    }
    let plugin_non_exec = PluginConfig::new("non-exec", &non_exec_file, vec!["agent".into()]);
    let err = SubprocessAdapter::preflight(&ctx, &plugin_non_exec).unwrap_err();
    assert!(err.to_string().contains("not executable"));
}

// ── 12. Parser Event Variants & Aliases ──────────────────────────────────────

#[test]
fn test_parse_plugin_event_all_variants() {
    // 1. Question raised
    match parse_plugin_event(r#"{"type":"question_raised","prompt":"Which file?"}"#) {
        Some(AdapterEvent::QuestionRaised { prompt }) => {
            assert_eq!(prompt, "Which file?");
        }
        other => panic!("expected QuestionRaised, got {:?}", other),
    }

    // 2. Rate limit signal
    match parse_plugin_event(r#"{"type":"rate_limit","back_off_secs":45}"#) {
        Some(AdapterEvent::RateLimitSignal { back_off_secs }) => {
            assert_eq!(back_off_secs, Some(45));
        }
        other => panic!("expected RateLimitSignal, got {:?}", other),
    }

    // 3. Paused / Resumed
    assert!(matches!(
        parse_plugin_event(r#"{"type":"paused"}"#),
        Some(AdapterEvent::Paused)
    ));
    assert!(matches!(
        parse_plugin_event(r#"{"type":"resumed"}"#),
        Some(AdapterEvent::Resumed)
    ));

    // 4. Snapshot produced
    match parse_plugin_event(r#"{"type":"snapshot_produced","summary":"step-3 checkpoint"}"#) {
        Some(AdapterEvent::SnapshotProduced { summary }) => {
            assert_eq!(summary, "step-3 checkpoint");
        }
        other => panic!("expected SnapshotProduced, got {:?}", other),
    }

    // 5. Start failed
    match parse_plugin_event(r#"{"type":"start_failed","reason":"invalid license key"}"#) {
        Some(AdapterEvent::StartFailed { reason }) => {
            assert_eq!(reason, "invalid license key");
        }
        other => panic!("expected StartFailed, got {:?}", other),
    }

    // 6. Whitespace and empty lines
    assert!(parse_plugin_event("").is_none());
    assert!(parse_plugin_event("   \t  \n").is_none());
}

// ── 13. Adversarial Challenger 1 & 2 Findings Verification ─────────────────────

#[tokio::test]
async fn test_subprocess_adapter_landlock_user_executable_allowlisting() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/maya".to_string());
    let custom_bin_dir = PathBuf::from(home)
        .join(".cache")
        .join(format!("ac_test_landlock_bin_{}", std::process::id()));
    fs::create_dir_all(&custom_bin_dir).expect("create custom_bin_dir");

    let script = create_mock_script(
        &custom_bin_dir,
        "custom_adapter.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"output","text":"landlock-user-exe-success"}'
printf '%s\n' '{"type":"completed","summary":"user-exe-completed"}'
exit 0
"#,
    );

    let tmp_ws = tempdir().expect("tempdir");
    let plugin = PluginConfig::new("user-dir-plugin", &script, vec!["user-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "user exe task".into(), "user-agent".into())
        .with_workspace(tmp_ws.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx)
        .expect("SubprocessAdapter::spawn should succeed with user-dir binary allowlisted in Landlock");

    let evt1 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt1, AdapterEvent::Ready));

    let evt2 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected OutputChunk event");
    match evt2 {
        AdapterEvent::OutputChunk { text, .. } => {
            assert_eq!(text, "landlock-user-exe-success");
        }
        other => panic!("expected OutputChunk, got {:?}", other),
    }

    let evt3 = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Completed event");
    match evt3 {
        AdapterEvent::Completed { summary } => {
            assert_eq!(summary, Some("user-exe-completed".to_string()));
        }
        other => panic!("expected Completed, got {:?}", other),
    }

    drop(handle);
    let _ = fs::remove_dir_all(&custom_bin_dir);
}

#[tokio::test]
async fn test_subprocess_adapter_lossy_non_utf8_stdout_handling() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "lossy_utf8.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
printf '%s\n' '{"type":"output","text":"pre-invalid-output"}'
printf '\xff\xfe\xfd\n'
printf '%s\n' '{"type":"output","text":"post-invalid-survived"}'
printf '%s\n' '{"type":"completed","summary":"lossy-utf8-success"}'
exit 0
"#,
    );

    let plugin = PluginConfig::new("lossy-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "lossy utf8 task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    let mut post_invalid_received = false;
    let mut completed_received = false;

    while let Some(evt) = recv_event(&mut event_rx, Duration::from_secs(3)).await {
        match evt {
            AdapterEvent::OutputChunk { text, .. } => {
                if text.contains("post-invalid-survived") {
                    post_invalid_received = true;
                }
            }
            AdapterEvent::Completed { summary } => {
                if summary == Some("lossy-utf8-success".to_string()) {
                    completed_received = true;
                    break;
                }
            }
            _ => {}
        }
    }

    assert!(
        post_invalid_received,
        "Stream parser must survive non-UTF8 bytes and read subsequent post-invalid output"
    );
    assert!(
        completed_received,
        "Completed event must arrive following non-UTF8 output chunks"
    );

    drop(handle);
}

#[tokio::test]
async fn test_subprocess_adapter_output_burst_drain_and_no_duplicate_completed() {
    let tmp = tempdir().expect("tempdir");
    let script = create_mock_script(
        tmp.path(),
        "burst.sh",
        r#"#!/bin/sh
printf '%s\n' '{"type":"ready"}'
for i in $(seq 1 500); do
    printf '{"type":"output","text":"burst_item_%d"}\n' "$i"
done
printf '%s\n' '{"type":"completed","summary":"burst_completed"}'
exit 0
"#,
    );

    let plugin = PluginConfig::new("burst-plugin", &script, vec!["test-agent".into()]);
    let ctx = SessionContext::new(Id::new(), "burst task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(1024);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    let mut received_burst_items = Vec::new();
    let mut completed_count = 0;
    let mut completed_summary = None;

    while let Some(evt) = recv_event(&mut event_rx, Duration::from_secs(5)).await {
        match evt {
            AdapterEvent::OutputChunk { text, .. } => {
                if text.starts_with("burst_item_") {
                    received_burst_items.push(text);
                }
            }
            AdapterEvent::Completed { summary } => {
                completed_count += 1;
                completed_summary = summary;
            }
            _ => {}
        }
    }

    // 1. All 500 burst items must be received in order with zero loss
    assert_eq!(
        received_burst_items.len(),
        500,
        "Expected all 500 burst items to be drained before completion"
    );
    for (idx, item) in received_burst_items.iter().enumerate() {
        assert_eq!(item, &format!("burst_item_{}", idx + 1));
    }

    // 2. Exactly one Completed event must be emitted (no duplicate from monitor task)
    assert_eq!(
        completed_count, 1,
        "Expected exactly 1 Completed event, got {}",
        completed_count
    );
    assert_eq!(completed_summary, Some("burst_completed".to_string()));

    drop(handle);
}

#[tokio::test]
async fn test_subprocess_adapter_process_group_grandchild_cleanup() {
    let tmp = tempdir().expect("tempdir");
    let gc_pid_file = tmp.path().join("grandchild.pid");

    let script = create_mock_script(
        tmp.path(),
        "grandchild_spawner.sh",
        r#"#!/bin/sh
sleep 120 &
GC_PID=$!
echo "$GC_PID" > "$1"
printf '%s\n' '{"type":"ready"}'
while true; do
    sleep 0.1
done
"#,
    );

    let plugin = PluginConfig::new("grandchild-plugin", &script, vec!["test-agent".into()])
        .with_arg(gc_pid_file.to_str().unwrap());

    let ctx = SessionContext::new(Id::new(), "grandchild task".into(), "test-agent".into())
        .with_workspace(tmp.path().to_str().unwrap());

    let (event_tx, mut event_rx) = mpsc::channel(32);
    let handle = SubprocessAdapter::spawn(&ctx, &plugin, event_tx).expect("spawn failed");

    // Wait for Ready
    let evt = recv_event(&mut event_rx, Duration::from_secs(5))
        .await
        .expect("expected Ready event");
    assert!(matches!(evt, AdapterEvent::Ready));

    // Read grandchild PID
    let mut gc_pid: Option<i32> = None;
    for _ in 0..20 {
        if let Ok(content) = fs::read_to_string(&gc_pid_file) {
            if let Ok(pid) = content.trim().parse::<i32>() {
                gc_pid = Some(pid);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let pid = gc_pid.expect("grandchild PID should be written to file");

    #[cfg(unix)]
    {
        // Verify grandchild is alive before drop
        assert_eq!(
            unsafe { libc::kill(pid, 0) },
            0,
            "Grandchild PID {} must be running before drop",
            pid
        );

        // Drop handle: should kill the process group (-pid), terminating the grandchild
        drop(handle);

        let mut terminated = false;
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if unsafe { libc::kill(pid, 0) } == -1 {
                terminated = true;
                break;
            }
        }

        assert!(
            terminated,
            "Grandchild process {} must be terminated by process group kill on handle drop",
            pid
        );
    }
}
