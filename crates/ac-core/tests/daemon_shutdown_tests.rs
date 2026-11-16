#[cfg(unix)]
#[tokio::test]
async fn test_daemon_graceful_shutdown_on_sigterm() {
    use std::io::Write;
    use std::time::Duration;

    let bin_path = env!("CARGO_BIN_EXE_agentcontrold");
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("daemon.sock");
    let db_path = tmp.path().join("events.db");
    let config_path = tmp.path().join("config.toml");

    let config_content = format!(
        r#"
socket_path = "{}"
db_path = "{}"
ws_enabled = false
"#,
        socket_path.display(),
        db_path.display()
    );

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    config_file.write_all(config_content.as_bytes()).unwrap();
    drop(config_file);

    let mut child = std::process::Command::new(bin_path)
        .env("AC_CONFIG", &config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn agentcontrold");

    let pid = child.id() as libc::pid_t;

    // Wait until socket file is created and listening
    let mut ready = false;
    for _ in 0..50 {
        if socket_path.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Daemon failed to create socket file in time");

    // Send SIGTERM
    let kill_res = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(kill_res, 0, "Failed to send SIGTERM to daemon");

    // Wait for process to exit
    let mut exited = false;
    for _ in 0..50 {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "Daemon did not exit successfully on SIGTERM: {:?}", status);
                exited = true;
                break;
            }
            None => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    assert!(exited, "Daemon did not exit after SIGTERM");

    // Verify socket file was cleaned up
    assert!(!socket_path.exists(), "IPC socket file was not removed on SIGTERM shutdown");
}

#[cfg(unix)]
#[tokio::test]
async fn test_daemon_graceful_shutdown_on_sigint() {
    use std::io::Write;
    use std::time::Duration;

    let bin_path = env!("CARGO_BIN_EXE_agentcontrold");
    let tmp = tempfile::tempdir().unwrap();
    let socket_path = tmp.path().join("daemon.sock");
    let db_path = tmp.path().join("events.db");
    let config_path = tmp.path().join("config.toml");

    let config_content = format!(
        r#"
socket_path = "{}"
db_path = "{}"
ws_enabled = false
"#,
        socket_path.display(),
        db_path.display()
    );

    let mut config_file = std::fs::File::create(&config_path).unwrap();
    config_file.write_all(config_content.as_bytes()).unwrap();
    drop(config_file);

    let mut child = std::process::Command::new(bin_path)
        .env("AC_CONFIG", &config_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to spawn agentcontrold");

    let pid = child.id() as libc::pid_t;

    // Wait until socket file is created and listening
    let mut ready = false;
    for _ in 0..50 {
        if socket_path.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Daemon failed to create socket file in time");

    // Send SIGINT
    let kill_res = unsafe { libc::kill(pid, libc::SIGINT) };
    assert_eq!(kill_res, 0, "Failed to send SIGINT to daemon");

    // Wait for process to exit
    let mut exited = false;
    for _ in 0..50 {
        match child.try_wait().unwrap() {
            Some(status) => {
                assert!(status.success(), "Daemon did not exit successfully on SIGINT: {:?}", status);
                exited = true;
                break;
            }
            None => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    assert!(exited, "Daemon did not exit after SIGINT");

    // Verify socket file was cleaned up
    assert!(!socket_path.exists(), "IPC socket file was not removed on SIGINT shutdown");
}
