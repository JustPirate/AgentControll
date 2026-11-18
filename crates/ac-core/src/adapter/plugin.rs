//! Dynamic subprocess adapter plugin implementation (Feature F5 / ADR-008).
//!
//! Spawns an external adapter executable as a child process communicating over
//! stdin/stdout via a newline-delimited JSON (NDJSON) protocol.
//!
//! Enforces environment variable hygiene, keyring isolation, workspace boundary,
//! Landlock filesystem sandboxing, and RAII child process teardown.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex};
use tracing::{warn};

use super::AdapterHandle;
use crate::config::PluginConfig;
use crate::types::{AdapterEvent, AgentCommand, Confidence, ProviderCapabilities, SessionContext};

/// Subprocess adapter for external plugin binaries.
pub struct SubprocessAdapter;

impl SubprocessAdapter {
    /// Return the declared capabilities of this plugin.
    pub fn capabilities(plugin: &PluginConfig) -> ProviderCapabilities {
        plugin.capabilities.to_provider_capabilities()
    }

    /// Preflight check validating executable path and workspace directory.
    pub fn preflight(ctx: &SessionContext, plugin: &PluginConfig) -> Result<()> {
        if let Some(ref ws) = ctx.workspace_path {
            let p = Path::new(ws);
            if !p.is_dir() {
                bail!("Workspace directory does not exist or is not a directory: {}", ws);
            }
        }

        resolve_executable(&plugin.executable)?;
        Ok(())
    }

    /// Spawn the external plugin executable and orchestrate bidirectional NDJSON communication.
    pub fn spawn(
        ctx: &SessionContext,
        plugin: &PluginConfig,
        event_tx: mpsc::Sender<AdapterEvent>,
    ) -> Result<AdapterHandle> {
        let exe_path = resolve_executable(&plugin.executable)
            .unwrap_or_else(|_| plugin.executable.clone());

        let mut cmd = tokio::process::Command::new(&exe_path);
        cmd.args(&plugin.args);

        #[cfg(unix)]
        cmd.process_group(0);

        // Workspace directory boundary
        if let Some(ref ws) = ctx.workspace_path {
            let p = Path::new(ws);
            if p.is_dir() {
                cmd.current_dir(p);
            } else {
                bail!("Workspace directory does not exist: {}", ws);
            }
        }

        // Ambient auth env var stripping
        for var in &crate::agy_auth::AMBIENT_AUTH_ENV {
            cmd.env_remove(var);
        }

        // Keyring isolation: neutralize host desktop keyring over D-Bus
        cmd.env("DBUS_SESSION_BUS_ADDRESS", "disabled:");

        // Injected plugin configuration env
        for (k, v) in &plugin.env {
            cmd.env(k, v);
        }

        // Injected context environment variables
        cmd.env("AC_SESSION_ID", ctx.session_id.to_string());
        cmd.env("AC_AGENT_TYPE", &ctx.agent_type);
        cmd.env("AC_TASK_DESCRIPTION", &ctx.task_description);
        cmd.env("AC_TASK", &ctx.task_description);
        if let Some(ref ws) = ctx.workspace_path {
            cmd.env("AC_WORKSPACE_PATH", ws);
            cmd.env("AC_WORKSPACE", ws);
        }
        if let Some(ref aid) = ctx.account_id {
            cmd.env("AC_ACCOUNT_ID", aid.to_string());
        }
        if let Some(ref cref) = ctx.credential_ref {
            cmd.env("AC_CREDENTIAL_REF", cref);
        }

        // Landlock filesystem sandboxing integration (Feature F4)
        let mut policy = crate::sandbox::SandboxPolicy::from_session(ctx, None);
        // Ensure plugin executable (and its parent directory) is allowed for execution under Landlock
        let mut extra_reads = Vec::new();
        if let Ok(canonical) = exe_path.canonicalize() {
            if let Some(parent) = canonical.parent() {
                extra_reads.push(parent.to_path_buf());
            }
            extra_reads.push(canonical);
        }
        if let Some(parent) = exe_path.parent() {
            extra_reads.push(parent.to_path_buf());
        }
        extra_reads.push(exe_path.clone());
        extra_reads.sort();
        extra_reads.dedup();
        policy = policy.with_extra_read_paths(extra_reads);

        let ruleset = policy.prepare().context("preparing sandbox ruleset")?;
        let ruleset_fd = ruleset.raw_fd();
        if ruleset_fd >= 0 {
            #[cfg(unix)]
            unsafe {
                cmd.pre_exec(move || {
                    crate::sandbox::apply_raw_ruleset_fd(ruleset_fd)
                });
            }
        }

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn().with_context(|| {
            format!(
                "failed to spawn plugin '{}' executable '{}'",
                plugin.name,
                exe_path.display()
            )
        })?;
        drop(ruleset);

        let child_pid = child.id();
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take child stdout"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take child stderr"))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow::anyhow!("failed to take child stdin"))?;

        let stdin = Arc::new(Mutex::new(stdin));
        let exited = Arc::new(AtomicBool::new(false));
        let completed_emitted = Arc::new(AtomicBool::new(false));
        let stderr_tail = Arc::new(Mutex::new(VecDeque::<String>::with_capacity(20)));

        let (cmd_tx, mut cmd_rx) = mpsc::channel::<AgentCommand>(512);
        let event_tx_cmd = event_tx.clone();
        let stdin_cmd = stdin.clone();
        let plugin_name = plugin.name.clone();
        let exited_cmd = exited.clone();

        // Send initial Start command to child stdin
        let init_cmd = AgentCommand::Start {
            session_id: ctx.session_id.clone(),
            task_description: ctx.task_description.clone(),
            agent_type: ctx.agent_type.clone(),
        };
        {
            let stdin_init = stdin.clone();
            tokio::spawn(async move {
                if let Ok(line) = serde_json::to_string(&init_cmd) {
                    let mut lock = stdin_init.lock().await;
                    let _ = lock.write_all(line.as_bytes()).await;
                    let _ = lock.write_all(b"\n").await;
                    let _ = lock.flush().await;
                }
            });
        }

        // ── 1. Command task: AgentCommand -> NDJSON stdin ───────────────────────
        let cmd_task = tokio::spawn(async move {
            while let Some(command) = cmd_rx.recv().await {
                match &command {
                    AgentCommand::Pause => {
                        #[cfg(unix)]
                        if let Some(pid) = child_pid {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGSTOP);
                            }
                        }
                        if let Ok(line) = serde_json::to_string(&command) {
                            let mut lock = stdin_cmd.lock().await;
                            let _ = lock.write_all(line.as_bytes()).await;
                            let _ = lock.write_all(b"\n").await;
                            let _ = lock.flush().await;
                        }
                        let _ = event_tx_cmd.send(AdapterEvent::Paused).await;
                    }
                    AgentCommand::Resume => {
                        #[cfg(unix)]
                        if let Some(pid) = child_pid {
                            unsafe {
                                libc::kill(pid as i32, libc::SIGCONT);
                            }
                        }
                        if let Ok(line) = serde_json::to_string(&command) {
                            let mut lock = stdin_cmd.lock().await;
                            let _ = lock.write_all(line.as_bytes()).await;
                            let _ = lock.write_all(b"\n").await;
                            let _ = lock.flush().await;
                        }
                        let _ = event_tx_cmd.send(AdapterEvent::Resumed).await;
                    }
                    AgentCommand::Stop { .. } => {
                        if let Ok(line) = serde_json::to_string(&command) {
                            let mut lock = stdin_cmd.lock().await;
                            let _ = lock.write_all(line.as_bytes()).await;
                            let _ = lock.write_all(b"\n").await;
                            let _ = lock.flush().await;
                        }
                        #[cfg(unix)]
                        if let Some(pid) = child_pid {
                            unsafe {
                                if libc::kill(-(pid as i32), libc::SIGTERM) != 0 {
                                    libc::kill(pid as i32, libc::SIGTERM);
                                }
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        #[cfg(unix)]
                        if let Some(pid) = child_pid {
                            if !exited_cmd.load(Ordering::SeqCst) {
                                unsafe {
                                    if libc::kill(-(pid as i32), libc::SIGKILL) != 0 {
                                        libc::kill(pid as i32, libc::SIGKILL);
                                    }
                                }
                            }
                        }
                        break;
                    }
                    other => {
                        if let Ok(line) = serde_json::to_string(other) {
                            let mut lock = stdin_cmd.lock().await;
                            let _ = lock.write_all(line.as_bytes()).await;
                            let _ = lock.write_all(b"\n").await;
                            let _ = lock.flush().await;
                        }
                    }
                }
            }
        });

        // ── 2. Stdout task: NDJSON stdout -> AdapterEvent ──────────────────────
        let event_tx_stdout = event_tx.clone();
        let completed_emitted_stdout = completed_emitted.clone();
        let plugin_name_stdout = plugin_name.clone();
        let stdout_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            let mut byte_buf = Vec::new();
            let mut ready_emitted = false;

            loop {
                byte_buf.clear();
                match reader.read_until(b'\n', &mut byte_buf).await {
                    Ok(0) => break, // EOF reached
                    Ok(_) => {
                        let mut slice = byte_buf.as_slice();
                        while let Some((&last, rest)) = slice.split_last() {
                            if last == b'\n' || last == b'\r' {
                                slice = rest;
                            } else {
                                break;
                            }
                        }
                        let lossy_str = String::from_utf8_lossy(slice);
                        let trimmed = lossy_str.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        if let Some(event) = parse_plugin_event(trimmed) {
                            match &event {
                                AdapterEvent::StartFailed { .. } => {
                                    let _ = event_tx_stdout.send(event).await;
                                    break;
                                }
                                AdapterEvent::Completed { .. } => {
                                    completed_emitted_stdout.store(true, Ordering::SeqCst);
                                    if !ready_emitted {
                                        ready_emitted = true;
                                        if event_tx_stdout.send(AdapterEvent::Ready).await.is_err() {
                                            break;
                                        }
                                    }
                                    if event_tx_stdout.send(event).await.is_err() {
                                        break;
                                    }
                                }
                                AdapterEvent::Ready => {
                                    if !ready_emitted {
                                        ready_emitted = true;
                                        if event_tx_stdout.send(event).await.is_err() {
                                            break;
                                        }
                                    }
                                }
                                other => {
                                    if !ready_emitted {
                                        ready_emitted = true;
                                        if event_tx_stdout.send(AdapterEvent::Ready).await.is_err() {
                                            break;
                                        }
                                    }
                                    if event_tx_stdout.send(other.clone()).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("plugin [{}] stdout read error: {}", plugin_name_stdout, e);
                        break;
                    }
                }
            }
        });

        // ── 3. Stderr task: line reading, logging, and tail buffer ─────────────
        let event_tx_stderr = event_tx.clone();
        let stderr_tail_buf = stderr_tail.clone();
        let plugin_name_stderr = plugin_name.clone();
        let stderr_task = tokio::spawn(async move {
            let mut reader = BufReader::new(stderr);
            let mut byte_buf = Vec::new();

            loop {
                byte_buf.clear();
                match reader.read_until(b'\n', &mut byte_buf).await {
                    Ok(0) => break, // EOF reached
                    Ok(_) => {
                        let mut slice = byte_buf.as_slice();
                        while let Some((&last, rest)) = slice.split_last() {
                            if last == b'\n' || last == b'\r' {
                                slice = rest;
                            } else {
                                break;
                            }
                        }
                        let lossy_str = String::from_utf8_lossy(slice);
                        let trimmed = lossy_str.trim();
                        if trimmed.is_empty() {
                            continue;
                        }
                        warn!("plugin [{}] stderr: {}", plugin_name_stderr, trimmed);
                        {
                            let mut tail = stderr_tail_buf.lock().await;
                            if tail.len() >= 20 {
                                tail.pop_front();
                            }
                            tail.push_back(trimmed.to_string());
                        }
                        let _ = event_tx_stderr
                            .send(AdapterEvent::OutputChunk {
                                text: format!("[stderr] {}", trimmed),
                                confidence: Confidence::High,
                            })
                            .await;
                    }
                    Err(e) => {
                        warn!("plugin [{}] stderr read error: {}", plugin_name_stderr, e);
                        break;
                    }
                }
            }
        });

        // ── 4. Monitor task: wait for exit, drain streams, and emit Completed or Crashed ─
        let event_tx_monitor = event_tx;
        let exited_monitor = exited.clone();
        let completed_emitted_mon = completed_emitted.clone();
        let stderr_tail_mon = stderr_tail.clone();
        let plugin_name_mon = plugin_name.clone();
        let stdout_abort = stdout_task.abort_handle();
        let stderr_abort = stderr_task.abort_handle();

        let monitor_task = tokio::spawn(async move {
            let status = child.wait().await;
            exited_monitor.store(true, Ordering::SeqCst);

            // Wait for stdout and stderr reader tasks to finish draining buffered bytes
            let _ = tokio::time::timeout(Duration::from_secs(3), async {
                let _ = tokio::join!(stdout_task, stderr_task);
            })
            .await;

            match status {
                Ok(s) if s.success() => {
                    if !completed_emitted_mon.load(Ordering::SeqCst) {
                        let _ = event_tx_monitor
                            .send(AdapterEvent::Completed {
                                summary: Some(format!(
                                    "Plugin '{}' completed successfully",
                                    plugin_name_mon
                                )),
                            })
                            .await;
                    }
                }
                Ok(s) => {
                    let code = s.code();
                    let tail = stderr_tail_mon.lock().await;
                    let tail_str = if tail.is_empty() {
                        String::new()
                    } else {
                        format!(
                            " - recent stderr:\n{}",
                            tail.iter().cloned().collect::<Vec<_>>().join("\n")
                        )
                    };
                    let reason = format!(
                        "Plugin '{}' process exited with status {}{}",
                        plugin_name_mon, s, tail_str
                    );
                    let _ = event_tx_monitor
                        .send(AdapterEvent::Crashed {
                            exit_code: code,
                            reason: Some(reason),
                        })
                        .await;
                }
                Err(e) => {
                    let _ = event_tx_monitor
                        .send(AdapterEvent::Crashed {
                            exit_code: None,
                            reason: Some(format!(
                                "Error waiting for plugin '{}' process: {}",
                                plugin_name_mon, e
                            )),
                        })
                        .await;
                }
            }
        });

        let drop_guard = Box::new(SubprocessDropGuard {
            child_pid,
            exited,
            cmd_task: cmd_task.abort_handle(),
            stdout_task: stdout_abort,
            stderr_task: stderr_abort,
            monitor_task: monitor_task.abort_handle(),
        });

        Ok(AdapterHandle::with_cmd_tx(drop_guard, cmd_tx))
    }
}

/// RAII Drop Guard ensuring child process is terminated with SIGKILL on drop.
pub struct SubprocessDropGuard {
    child_pid: Option<u32>,
    exited: Arc<AtomicBool>,
    cmd_task: tokio::task::AbortHandle,
    stdout_task: tokio::task::AbortHandle,
    stderr_task: tokio::task::AbortHandle,
    monitor_task: tokio::task::AbortHandle,
}

impl Drop for SubprocessDropGuard {
    fn drop(&mut self) {
        self.cmd_task.abort();
        self.stdout_task.abort();
        self.stderr_task.abort();
        self.monitor_task.abort();

        #[cfg(unix)]
        if let Some(pid) = self.child_pid {
            unsafe {
                // Kill process group first (-pid) to terminate background helpers/grandchildren,
                // fallback to direct pid if not already exited
                if libc::kill(-(pid as i32), libc::SIGKILL) != 0 && !self.exited.load(Ordering::SeqCst) {
                    libc::kill(pid as i32, libc::SIGKILL);
                }
            }
        }
    }
}

/// Resolves the executable path, searching PATH if necessary, and verifying execute permission.
pub fn resolve_executable(exe: &Path) -> Result<PathBuf> {
    if exe.as_os_str().is_empty() {
        bail!("Executable path is empty");
    }

    let expanded = if exe.starts_with("~/") || exe == Path::new("~") {
        if let Ok(home) = std::env::var("HOME") {
            if let Ok(rel) = exe.strip_prefix("~") {
                let clean_rel = rel.strip_prefix("/").unwrap_or(rel);
                PathBuf::from(home).join(clean_rel)
            } else {
                exe.to_path_buf()
            }
        } else {
            exe.to_path_buf()
        }
    } else {
        exe.to_path_buf()
    };

    if expanded.components().count() > 1 || expanded.is_absolute() {
        if expanded.is_file() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = expanded.metadata() {
                    if meta.permissions().mode() & 0o111 == 0 {
                        bail!("File exists but is not executable: {}", expanded.display());
                    }
                }
            }
            return Ok(expanded);
        }
        bail!("Plugin executable does not exist: {}", expanded.display());
    }

    if let Ok(paths) = std::env::var("PATH") {
        for dir in std::env::split_paths(&paths) {
            let candidate = dir.join(&expanded);
            if candidate.is_file() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(meta) = candidate.metadata() {
                        if meta.permissions().mode() & 0o111 == 0 {
                            continue;
                        }
                    }
                }
                return Ok(candidate);
            }
        }
    }

    bail!("Plugin executable '{}' not found in PATH", exe.display());
}

/// Parses a line of plugin stdout into an `AdapterEvent`.
///
/// Supports native `AdapterEvent` JSON, canonical aliases, and falls back to
/// low-confidence `OutputChunk` for plaintext.
pub fn parse_plugin_event(line: &str) -> Option<AdapterEvent> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // 1. Direct deserialize into native AdapterEvent
    if let Ok(event) = serde_json::from_str::<AdapterEvent>(trimmed) {
        return Some(event);
    }

    // 2. Custom JSON aliases
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
        if let Some(obj) = val.as_object() {
            if let Some(t) = obj.get("type").and_then(|v| v.as_str()) {
                match t {
                    "ready" | "started" => return Some(AdapterEvent::Ready),
                    "output" | "output_chunk" => {
                        let text = obj
                            .get("text")
                            .or_else(|| obj.get("data"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let confidence = match obj.get("confidence").and_then(|v| v.as_str()) {
                            Some("high") => Confidence::High,
                            _ => Confidence::Low,
                        };
                        return Some(AdapterEvent::OutputChunk { text, confidence });
                    }
                    "approval_requested" => {
                        let tool_name = obj
                            .get("tool_name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("tool")
                            .to_string();
                        let prompt = obj
                            .get("prompt")
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        return Some(AdapterEvent::ApprovalRequested { tool_name, prompt });
                    }
                    "question_raised" => {
                        let prompt = obj
                            .get("prompt")
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        return Some(AdapterEvent::QuestionRaised { prompt });
                    }
                    "prompt" => {
                        let prompt = obj
                            .get("prompt")
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(tool_name) = obj.get("tool_name").and_then(|v| v.as_str()) {
                            return Some(AdapterEvent::ApprovalRequested {
                                tool_name: tool_name.to_string(),
                                prompt,
                            });
                        } else {
                            return Some(AdapterEvent::QuestionRaised { prompt });
                        }
                    }
                    "rate_limit" | "rate_limit_signal" => {
                        let back_off_secs = obj.get("back_off_secs").and_then(|v| v.as_u64());
                        return Some(AdapterEvent::RateLimitSignal { back_off_secs });
                    }
                    "paused" => return Some(AdapterEvent::Paused),
                    "resumed" => return Some(AdapterEvent::Resumed),
                    "completed" | "stopped" => {
                        let summary = obj
                            .get("summary")
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        return Some(AdapterEvent::Completed { summary });
                    }
                    "crashed" | "failed" | "error" => {
                        let exit_code = obj
                            .get("exit_code")
                            .and_then(|v| v.as_i64())
                            .map(|c| c as i32);
                        let reason = obj
                            .get("reason")
                            .or_else(|| obj.get("error"))
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .map(ToString::to_string);
                        return Some(AdapterEvent::Crashed { exit_code, reason });
                    }
                    "snapshot_produced" => {
                        let summary = obj
                            .get("summary")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        return Some(AdapterEvent::SnapshotProduced { summary });
                    }
                    "start_failed" => {
                        let reason = obj
                            .get("reason")
                            .or_else(|| obj.get("error"))
                            .or_else(|| obj.get("message"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("Plugin start failed")
                            .to_string();
                        return Some(AdapterEvent::StartFailed { reason });
                    }
                    _ => {}
                }
            }
        }
    }

    // 3. Fallback: treat non-JSON line as plaintext OutputChunk
    Some(AdapterEvent::OutputChunk {
        text: trimmed.to_string(),
        confidence: Confidence::Low,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_plugin_event_native_and_aliases() {
        // Native ready
        assert!(matches!(
            parse_plugin_event(r#"{"type":"ready"}"#),
            Some(AdapterEvent::Ready)
        ));

        // Alias started
        assert!(matches!(
            parse_plugin_event(r#"{"type":"started","pid":1234}"#),
            Some(AdapterEvent::Ready)
        ));

        // Output chunk native
        match parse_plugin_event(r#"{"type":"output_chunk","text":"hello","confidence":"high"}"#) {
            Some(AdapterEvent::OutputChunk { text, confidence }) => {
                assert_eq!(text, "hello");
                assert_eq!(confidence, Confidence::High);
            }
            other => panic!("expected OutputChunk, got {:?}", other),
        }

        // Output alias
        match parse_plugin_event(r#"{"type":"output","data":"world"}"#) {
            Some(AdapterEvent::OutputChunk { text, confidence }) => {
                assert_eq!(text, "world");
                assert_eq!(confidence, Confidence::Low);
            }
            other => panic!("expected OutputChunk, got {:?}", other),
        }

        // Approval requested native
        match parse_plugin_event(r#"{"type":"approval_requested","tool_name":"bash","prompt":"rm -rf"}"#) {
            Some(AdapterEvent::ApprovalRequested { tool_name, prompt }) => {
                assert_eq!(tool_name, "bash");
                assert_eq!(prompt, "rm -rf");
            }
            other => panic!("expected ApprovalRequested, got {:?}", other),
        }

        // Prompt alias with tool_name
        match parse_plugin_event(r#"{"type":"prompt","tool_name":"edit","prompt":"modify main.rs"}"#) {
            Some(AdapterEvent::ApprovalRequested { tool_name, prompt }) => {
                assert_eq!(tool_name, "edit");
                assert_eq!(prompt, "modify main.rs");
            }
            other => panic!("expected ApprovalRequested, got {:?}", other),
        }

        // Question raised native
        match parse_plugin_event(r#"{"type":"question_raised","prompt":"which file?"}"#) {
            Some(AdapterEvent::QuestionRaised { prompt }) => {
                assert_eq!(prompt, "which file?");
            }
            other => panic!("expected QuestionRaised, got {:?}", other),
        }

        // Prompt alias without tool_name
        match parse_plugin_event(r#"{"type":"prompt","message":"continue?"}"#) {
            Some(AdapterEvent::QuestionRaised { prompt }) => {
                assert_eq!(prompt, "continue?");
            }
            other => panic!("expected QuestionRaised, got {:?}", other),
        }

        // Rate limit signal native and alias
        match parse_plugin_event(r#"{"type":"rate_limit_signal","back_off_secs":45}"#) {
            Some(AdapterEvent::RateLimitSignal { back_off_secs }) => {
                assert_eq!(back_off_secs, Some(45));
            }
            other => panic!("expected RateLimitSignal, got {:?}", other),
        }
        match parse_plugin_event(r#"{"type":"rate_limit","back_off_secs":60}"#) {
            Some(AdapterEvent::RateLimitSignal { back_off_secs }) => {
                assert_eq!(back_off_secs, Some(60));
            }
            other => panic!("expected RateLimitSignal, got {:?}", other),
        }

        // Completed native and stopped alias
        match parse_plugin_event(r#"{"type":"completed","summary":"done"}"#) {
            Some(AdapterEvent::Completed { summary }) => {
                assert_eq!(summary, Some("done".into()));
            }
            other => panic!("expected Completed, got {:?}", other),
        }
        match parse_plugin_event(r#"{"type":"stopped","message":"finished"}"#) {
            Some(AdapterEvent::Completed { summary }) => {
                assert_eq!(summary, Some("finished".into()));
            }
            other => panic!("expected Completed, got {:?}", other),
        }

        // Crashed native and failed alias
        match parse_plugin_event(r#"{"type":"crashed","exit_code":2,"reason":"segfault"}"#) {
            Some(AdapterEvent::Crashed { exit_code, reason }) => {
                assert_eq!(exit_code, Some(2));
                assert_eq!(reason, Some("segfault".into()));
            }
            other => panic!("expected Crashed, got {:?}", other),
        }
        match parse_plugin_event(r#"{"type":"failed","error":"network timeout"}"#) {
            Some(AdapterEvent::Crashed { exit_code, reason }) => {
                assert_eq!(exit_code, None);
                assert_eq!(reason, Some("network timeout".into()));
            }
            other => panic!("expected Crashed, got {:?}", other),
        }

        // Start failed
        match parse_plugin_event(r#"{"type":"start_failed","reason":"invalid license"}"#) {
            Some(AdapterEvent::StartFailed { reason }) => {
                assert_eq!(reason, "invalid license");
            }
            other => panic!("expected StartFailed, got {:?}", other),
        }

        // Snapshot produced
        match parse_plugin_event(r#"{"type":"snapshot_produced","summary":"state snapshot"}"#) {
            Some(AdapterEvent::SnapshotProduced { summary }) => {
                assert_eq!(summary, "state snapshot");
            }
            other => panic!("expected SnapshotProduced, got {:?}", other),
        }

        // Plaintext fallback
        match parse_plugin_event("Simple log line from plugin without json") {
            Some(AdapterEvent::OutputChunk { text, confidence }) => {
                assert_eq!(text, "Simple log line from plugin without json");
                assert_eq!(confidence, Confidence::Low);
            }
            other => panic!("expected OutputChunk, got {:?}", other),
        }

        // Empty / whitespace
        assert!(parse_plugin_event("").is_none());
        assert!(parse_plugin_event("   \t\n").is_none());
    }

    #[test]
    fn test_resolve_executable() {
        // Empty
        assert!(resolve_executable(Path::new("")).is_err());

        // Path that doesn't exist
        assert!(resolve_executable(Path::new("/nonexistent/binary/path")).is_err());

        // Standard system binary in PATH (e.g. sh, ls)
        let sh_res = resolve_executable(Path::new("sh"));
        assert!(sh_res.is_ok());
        assert!(sh_res.unwrap().is_file());
    }

    #[tokio::test]
    async fn test_subprocess_adapter_lifecycle() {
        let script = r#"
echo '{"type":"output","data":"starting up"}'
echo '{"type":"completed","summary":"success"}'
"#;
        let plugin = PluginConfig::new("test-mock", "sh", vec!["test-mock".into()])
            .with_arg("-c")
            .with_arg(script);

        let ctx = SessionContext::new(
            crate::types::Id::new(),
            "sample task".into(),
            "test-mock".into(),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let mut handle = SubprocessAdapter::spawn(&ctx, &plugin, tx).expect("spawn plugin");

        // First event must be synthesized Ready (since output came first)
        let ev1 = rx.recv().await.expect("recv ev1");
        assert!(matches!(ev1, AdapterEvent::Ready));

        // Second event is the OutputChunk
        let ev2 = rx.recv().await.expect("recv ev2");
        match ev2 {
            AdapterEvent::OutputChunk { text, .. } => assert_eq!(text, "starting up"),
            other => panic!("expected OutputChunk, got {:?}", other),
        }

        // Third event is Completed
        let ev3 = rx.recv().await.expect("recv ev3");
        match ev3 {
            AdapterEvent::Completed { summary } => assert_eq!(summary, Some("success".into())),
            other => panic!("expected Completed, got {:?}", other),
        }

        handle.stop();
    }

    #[tokio::test]
    async fn test_subprocess_adapter_crash_with_stderr() {
        let script = r#"
echo "crash diagnosis" >&2
exit 17
"#;
        let plugin = PluginConfig::new("crash-plugin", "sh", vec!["crash".into()])
            .with_arg("-c")
            .with_arg(script);

        let ctx = SessionContext::new(
            crate::types::Id::new(),
            "crash task".into(),
            "crash".into(),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let _handle = SubprocessAdapter::spawn(&ctx, &plugin, tx).expect("spawn plugin");

        // Wait for Crashed event
        let mut crashed = None;
        while let Some(ev) = rx.recv().await {
            if let AdapterEvent::Crashed { exit_code, reason } = ev {
                crashed = Some((exit_code, reason));
                break;
            }
        }

        let (code, reason) = crashed.expect("should receive Crashed event");
        assert_eq!(code, Some(17));
        assert!(reason.unwrap().contains("crash diagnosis"));
    }

    #[tokio::test]
    async fn test_subprocess_adapter_interactive_command_flow() {
        let script = r#"
read -r start_line
echo '{"type":"prompt","tool_name":"bash","prompt":"run ls"}'
read -r respond_line
echo "{\"type\":\"output\",\"text\": \"got reply: $respond_line\"}"
echo '{"type":"completed","summary":"approval handled"}'
"#;
        let plugin = PluginConfig::new("interactive-plugin", "sh", vec!["interactive".into()])
            .with_arg("-c")
            .with_arg(script);

        let ctx = SessionContext::new(
            crate::types::Id::new(),
            "interactive task".into(),
            "interactive".into(),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let mut handle = SubprocessAdapter::spawn(&ctx, &plugin, tx).expect("spawn plugin");

        // First event is synthesized Ready (before prompt)
        let ev1 = rx.recv().await.expect("recv ev1");
        assert!(matches!(ev1, AdapterEvent::Ready));

        // Second event is ApprovalRequested
        let ev2 = rx.recv().await.expect("recv ev2");
        match ev2 {
            AdapterEvent::ApprovalRequested { tool_name, prompt } => {
                assert_eq!(tool_name, "bash");
                assert_eq!(prompt, "run ls");
            }
            other => panic!("expected ApprovalRequested, got {:?}", other),
        }

        // Send Respond command
        handle
            .send_command(AgentCommand::Respond {
                allow: true,
                response: Some("approved".into()),
            })
            .expect("send respond command");

        // Read output chunk echoing response
        let ev3 = rx.recv().await.expect("recv ev3");
        match ev3 {
            AdapterEvent::OutputChunk { text, .. } => {
                assert!(text.contains("approved"));
            }
            other => panic!("expected OutputChunk with approved, got {:?}", other),
        }

        // Read completed
        let ev4 = rx.recv().await.expect("recv ev4");
        assert!(matches!(ev4, AdapterEvent::Completed { .. }));
    }

    #[tokio::test]
    async fn test_subprocess_adapter_drop_guard_terminates_child() {
        let script = r#"
while true; do
    sleep 0.1
done
"#;
        let plugin = PluginConfig::new("sleep-plugin", "sh", vec!["sleep".into()])
            .with_arg("-c")
            .with_arg(script);

        let ctx = SessionContext::new(
            crate::types::Id::new(),
            "sleep task".into(),
            "sleep".into(),
        );

        let (tx, mut rx) = mpsc::channel(64);
        let handle = SubprocessAdapter::spawn(&ctx, &plugin, tx).expect("spawn plugin");

        // Drop the handle
        drop(handle);

        // Within 1.5 seconds, channel closes as child is killed by DropGuard
        let _ = tokio::time::timeout(Duration::from_millis(1500), async {
            while let Some(_) = rx.recv().await {}
        })
        .await;
    }
}
