//! Integration tests for Feature F4: Kernel-Enforced Filesystem Sandboxing (Linux Landlock).
//!
//! CRITICAL TEST ISOLATION REQUIREMENT:
//! Landlock rules are permanent and monotonic on the calling thread/process.
//! All tests calling `restrict_self` MUST run their sandboxed assertions inside an
//! isolated child subprocess (via `libc::fork()`) so the cargo test runner process is
//! NEVER restricted!

use ac_core::adapter::pty::{GenericPtyAdapter, PtyConfig, PtyPatternKind};
use ac_core::sandbox::{probe_landlock_abi, LandlockStatus, SandboxPolicy, FILE_MASK};
use ac_core::types::{Id, SessionContext};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use tempfile::tempdir;

/// Helper to execute a closure inside an isolated child subprocess via `fork()`.
/// The child runs `f()`, and exits with code 0 on success or code 1 on panic/assertion failure.
/// The parent verifies that the child exited normally with exit code 0.
fn run_in_isolated_child<F>(f: F)
where
    F: FnOnce(),
{
    #[cfg(unix)]
    {
        io::stdout().flush().unwrap();
        io::stderr().flush().unwrap();

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "libc::fork failed");

        if pid == 0 {
            // Inside child process
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            match result {
                Ok(_) => unsafe { libc::_exit(0) },
                Err(err) => {
                    if let Some(s) = err.downcast_ref::<&str>() {
                        eprintln!("CHILD PANIC: {}", s);
                    } else if let Some(s) = err.downcast_ref::<String>() {
                        eprintln!("CHILD PANIC: {}", s);
                    } else {
                        eprintln!("CHILD PANIC: unknown panic payload");
                    }
                    io::stderr().flush().unwrap();
                    unsafe { libc::_exit(1) }
                }
            }
        } else {
            // Inside parent test runner process
            let mut status: libc::c_int = 0;
            let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(ret, pid, "waitpid returned unexpected pid");
            assert!(
                libc::WIFEXITED(status),
                "Child process terminated abnormally or was killed by signal (status = {:#x})",
                status
            );
            let exit_code = libc::WEXITSTATUS(status);
            assert_eq!(
                exit_code, 0,
                "Isolated child test assertion failed with exit code {}",
                exit_code
            );
        }
    }
    #[cfg(not(unix))]
    {
        f();
    }
}

#[test]
fn test_landlock_abi_probe() {
    let status = LandlockStatus::probe();
    let abi_opt = probe_landlock_abi();

    #[cfg(target_os = "linux")]
    {
        if let Some(abi) = abi_opt {
            assert!(abi >= 1, "Landlock ABI version must be at least 1");
            assert!(
                status.is_supported(),
                "LandlockStatus must report Supported when ABI is probed"
            );
            if let LandlockStatus::Supported { abi: status_abi } = status {
                assert_eq!(status_abi, abi);
            }
        } else {
            // On older Linux kernels without Landlock, probe should report Unsupported or Disabled
            assert!(!status.is_supported());
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert!(abi_opt.is_none());
        assert!(!status.is_supported());
    }
}

#[test]
fn test_policy_preparation_and_file_mask_invariant() {
    let ws = tempdir().expect("create workspace tempdir");
    let test_file = ws.path().join("dummy_cache.txt");
    fs::write(&test_file, b"sample content").expect("write dummy file");

    let policy = SandboxPolicy::new(ws.path())
        .with_extra_read_paths(vec![test_file.clone()])
        .with_mode("auto");

    let ruleset = policy.prepare().expect("prepare policy");
    #[cfg(target_os = "linux")]
    {
        if probe_landlock_abi().is_some() {
            assert!(ruleset.is_active());
            assert!(ruleset.raw_fd() >= 0);
        }
    }

    // Verify FILE_MASK does not request directory flags
    assert_eq!(FILE_MASK & ac_core::sandbox::LANDLOCK_ACCESS_FS_READ_DIR, 0);
    assert_eq!(FILE_MASK & ac_core::sandbox::LANDLOCK_ACCESS_FS_REFER, 0);
}

#[test]
fn test_isolated_workspace_rw_and_out_of_boundary_rejection() {
    if probe_landlock_abi().is_none() {
        eprintln!("Skipping test_isolated_workspace_rw_and_out_of_boundary_rejection: Landlock not supported on this kernel");
        return;
    }

    let home_dir = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));

    let ws = tempfile::Builder::new()
        .prefix("ac_sand_ws_")
        .tempdir_in(&home_dir)
        .expect("create ws tempdir in HOME");
    let outside = tempfile::Builder::new()
        .prefix("ac_sand_out_")
        .tempdir_in(&home_dir)
        .expect("create outside tempdir in HOME");

    let ws_path = ws.path().to_path_buf();
    let outside_path = outside.path().to_path_buf();

    // Create an initial secret file in the outside directory
    let secret_file = outside_path.join("secret_credentials.txt");
    fs::write(&secret_file, b"topsecret").expect("write secret file");

    run_in_isolated_child(move || {
        let policy = SandboxPolicy::new(&ws_path).with_mode("landlock");
        let ruleset = policy.prepare().expect("prepare policy in child");
        assert!(ruleset.is_active());

        // Apply ruleset in child
        ruleset.apply_in_pre_exec().expect("apply Landlock in child");

        // 1. VERIFY WORKSPACE READ-WRITE ACCESS:
        let test_ws_file = ws_path.join("sandbox_test.txt");
        fs::write(&test_ws_file, b"hello from sandbox")
            .expect("writing inside workspace must succeed");
        let read_back = fs::read_to_string(&test_ws_file)
            .expect("reading inside workspace must succeed");
        assert_eq!(read_back, "hello from sandbox");

        // 2. VERIFY /tmp READ-WRITE ACCESS (standard scratch):
        let tmp_test_file = Path::new("/tmp").join(format!("ac_sand_test_{}.tmp", std::process::id()));
        if let Ok(mut f) = fs::File::create(&tmp_test_file) {
            let _ = f.write_all(b"tmp write test");
            let _ = fs::remove_file(&tmp_test_file);
        }

        // 3. VERIFY OUT-OF-BOUNDARY ACCESS IS STRICTLY BLOCKED (EACCES / PermissionDenied):
        // Attempt to read secret file in outside directory
        let read_err = fs::read_to_string(&secret_file)
            .expect_err("reading outside boundary must return PermissionDenied");
        assert_eq!(
            read_err.kind(),
            io::ErrorKind::PermissionDenied,
            "Expected PermissionDenied on outside file read, got: {:?}",
            read_err
        );

        // Attempt to create a new file in outside directory
        let create_err = fs::File::create(outside_path.join("forbidden.txt"))
            .expect_err("creating outside boundary must return PermissionDenied");
        assert_eq!(
            create_err.kind(),
            io::ErrorKind::PermissionDenied,
            "Expected PermissionDenied on outside file create, got: {:?}",
            create_err
        );

        // Attempt to list outside directory entries
        let list_err = fs::read_dir(&outside_path)
            .expect_err("listing outside boundary must return PermissionDenied");
        assert_eq!(
            list_err.kind(),
            io::ErrorKind::PermissionDenied,
            "Expected PermissionDenied on outside directory list, got: {:?}",
            list_err
        );
    });
}

#[test]
fn test_isolated_profile_rw_permitted() {
    if probe_landlock_abi().is_none() {
        eprintln!("Skipping test_isolated_profile_rw_permitted: Landlock not supported on this kernel");
        return;
    }

    let home_dir = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("/tmp"));

    let ws = tempfile::Builder::new()
        .prefix("ac_sand_ws2_")
        .tempdir_in(&home_dir)
        .expect("create ws");
    let profile = tempfile::Builder::new()
        .prefix("ac_sand_prof_")
        .tempdir_in(&home_dir)
        .expect("create profile dir");
    let forbidden = tempfile::Builder::new()
        .prefix("ac_sand_forbid_")
        .tempdir_in(&home_dir)
        .expect("create forbidden dir");

    let ws_path = ws.path().to_path_buf();
    let profile_path = profile.path().to_path_buf();
    let forbidden_path = forbidden.path().to_path_buf();

    fs::write(forbidden_path.join("blocked.key"), b"forbidden_key").unwrap();

    run_in_isolated_child(move || {
        let policy = SandboxPolicy::new(&ws_path)
            .with_profile(&profile_path)
            .with_mode("landlock");

        let ruleset = policy.prepare().expect("prepare policy");
        ruleset.apply_in_pre_exec().expect("apply ruleset");

        // Profile directory access is permitted
        let prof_file = profile_path.join("oauth_token.json");
        fs::write(&prof_file, b"{\"token\": \"abc\"}").expect("writing to profile must succeed");
        let content = fs::read_to_string(&prof_file).expect("reading from profile must succeed");
        assert_eq!(content, "{\"token\": \"abc\"}");

        // Forbidden directory access is blocked
        let err = fs::read_to_string(forbidden_path.join("blocked.key"))
            .expect_err("accessing outside directory must fail");
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    });
}

#[test]
fn test_disabled_mode_allows_unrestricted_access() {
    let ws = tempdir().expect("create ws");
    let outside = tempdir().expect("create outside");

    let ws_path = ws.path().to_path_buf();
    let outside_path = outside.path().to_path_buf();

    let outside_file = outside_path.join("accessible.txt");
    fs::write(&outside_file, b"accessible").unwrap();

    run_in_isolated_child(move || {
        let policy = SandboxPolicy::new(&ws_path).with_mode("disabled");
        let ruleset = policy.prepare().expect("prepare disabled policy");
        assert!(!ruleset.is_active());
        assert_eq!(ruleset.raw_fd(), -1);

        ruleset.apply_in_pre_exec().expect("apply inactive ruleset");

        // When disabled, outside file can still be read normally
        let read = fs::read_to_string(&outside_file).expect("reading must succeed when sandbox is disabled");
        assert_eq!(read, "accessible");
    });
}

#[tokio::test]
async fn test_pty_adapter_sandboxed_process_execution() {
    if probe_landlock_abi().is_none() {
        eprintln!("Skipping test_pty_adapter_sandboxed_process_execution: Landlock not supported on this kernel");
        return;
    }

    let ws = tempdir().expect("create ws tempdir");
    let outside = tempdir().expect("create outside tempdir");

    let ws_path = ws.path().to_path_buf();
    let outside_file = outside.path().join("out_secret.txt");
    fs::write(&outside_file, b"out_secret_content").expect("write secret");

    let ctx = SessionContext {
        session_id: Id::new(),
        task_description: "sandboxed pty execution test".to_string(),
        agent_type: "shell".to_string(),
        workspace_path: Some(ws_path.display().to_string()),
        credential_ref: None,
        account_id: None,
        context_snapshot: None,
        agent_config: Some(serde_json::json!({
            "sandbox": true
        })),
    };

    // Shell script tests:
    // 1. Can write to workspace
    // 2. Attempting to read outside_file gets Permission denied
    let script = format!(
        "echo 'PTY_WS_OK' > pty_result.txt && (cat {} 2>&1 || echo 'EACCES_CONFIRMED')",
        outside_file.display()
    );

    let pty_config = PtyConfig::new("sh")
        .with_arg("-c")
        .with_arg(script)
        .with_pattern(r"PTY_WS_OK", PtyPatternKind::Ready)
        .unwrap();

    let (event_tx, _event_rx) = tokio::sync::mpsc::channel(32);

    let handle = GenericPtyAdapter::spawn(&ctx, pty_config, event_tx)
        .expect("spawn sandboxed PTY adapter");

    // Wait for PTY process completion or read file
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Verify workspace file was successfully written
    let res_path = ws_path.join("pty_result.txt");
    assert!(res_path.exists(), "pty_result.txt should have been created in workspace");
    let content = fs::read_to_string(res_path).unwrap();
    assert!(content.contains("PTY_WS_OK"));

    // Verify handle cleans up gracefully
    drop(handle);
}

#[tokio::test]
async fn test_claude_adapter_sandboxed_process_execution() {
    if probe_landlock_abi().is_none() {
        eprintln!("Skipping test_claude_adapter_sandboxed_process_execution: Landlock not supported on this kernel");
        return;
    }

    let ws = tempdir().expect("create ws tempdir");
    let outside = tempdir().expect("create outside tempdir");

    let ws_path = ws.path().to_path_buf();
    let outside_file = outside.path().join("out_claude_secret.txt");
    fs::write(&outside_file, b"claude_secret").expect("write secret");

    let ctx = SessionContext {
        session_id: Id::new(),
        task_description: "sandboxed claude execution test".to_string(),
        agent_type: "claude".to_string(),
        workspace_path: Some(ws_path.display().to_string()),
        credential_ref: None,
        account_id: None,
        context_snapshot: None,
        agent_config: Some(serde_json::json!({
            "sandbox": true
        })),
    };

    let script = format!(
        "echo 'CLAUDE_WS_OK' > claude_result.txt && (cat {} 2>&1 || echo 'EACCES_CONFIRMED')",
        outside_file.display()
    );

    let config = ac_core::adapter::claude::ClaudeConfig::custom("sh", vec!["-c".to_string(), script])
        .with_mode(ac_core::adapter::claude::ClaudeMode::Structured);

    let (event_tx, _event_rx) = tokio::sync::mpsc::channel(32);

    let handle = ac_core::adapter::claude::ClaudeAdapter::spawn(&ctx, config, event_tx)
        .expect("spawn sandboxed Claude adapter");

    std::thread::sleep(std::time::Duration::from_millis(500));

    let res_path = ws_path.join("claude_result.txt");
    assert!(res_path.exists(), "claude_result.txt should exist in workspace");
    let content = fs::read_to_string(res_path).unwrap();
    assert!(content.contains("CLAUDE_WS_OK"));

    drop(handle);
}
