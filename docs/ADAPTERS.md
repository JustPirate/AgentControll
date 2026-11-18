# Adapter Architecture & Development

Adapters are the integration bridges that connect external coding agent CLIs to Agent Control's event-driven state machine, PTY multiplexer, and permission model.

---

## 1. Architecture Overview

Agent Control communicates with agents via an asynchronous, event-driven contract:

```
┌─────────────────────────────────────────────────────────────┐
│                    SessionManager                           │
└──────────────┬───────────────────────────────▲──────────────┘
               │ SessionContext                │ AdapterEvent
               ▼                               │ (Started, Output,
┌──────────────────────────────────────────┐   │  Prompt, Stopped)
│          AdapterFactory                  │   │
│  (Composite / Pty / Claude / Mock)       │   │
└──────────────┬───────────────────────────┴───┘
               │ spawns
               ▼
┌──────────────────────────────────────────┐
│              AdapterHandle               │
│      - Drop guard / process killer       │
│      - Command channel (AgentCommand)    │
└──────────────────────────────────────────┘
```

### Key Components

- **`AdapterFactory`**: Trait defining how to query agent capabilities, perform preflight validation, and spawn active sessions.
- **`AdapterHandle`**: RAII handle holding process control channels and cleanup drop guards. When an `AdapterHandle` is dropped or receives `Stop`, it safely shuts down the agent child process.
- **`SessionContext`**: Carries metadata required to spawn the agent, including `session_id`, `project_dir`, `account_id`, `agent_config`, and `launch_options`.
- **`AdapterEvent`**: Asynchronous events emitted by the adapter back to the session manager:
  - `Started`: Agent process spawned and PID assigned.
  - `Output(Bytes)`: Terminal bytes or structured text emitted by agent.
  - `Prompt(InteractionId, PromptData)`: Agent is awaiting user input or permission confirmation.
  - `Stopped(ExitStatus)`: Agent completed execution.
  - `Failed(Error)`: Fatal execution or runtime error.

---

## 2. Built-in Adapters

### `PtyAdapter` (`crates/ac-core/src/adapter/pty.rs`)
- Manages pseudo-terminal (PTY) allocation using `portable-pty`.
- Spawns agents like Antigravity (`agy`) inside an isolated PTY slave.
- Reads raw terminal streams and processes them through `decode_utf8_stream` to ensure multi-byte UTF-8 glyphs are never corrupted when split across read chunks.
- Forwards terminal window resizes (`SIGWINCH` / `set_size`) dynamically.

### `ClaudeAdapter` (`crates/ac-core/src/adapter/claude.rs`)
- Integrates with Anthropic's Claude Code CLI.
- Handles standard environment variables, prompt injection, and process monitoring.

### `MockAdapter` (`crates/ac-core/src/adapter/mock.rs`)
- Synthetic agent used for unit and integration testing without external dependencies.
- Can simulate delays, simulated user prompts, crashes, and rapid output bursts.

---

## 3. Dynamic Subprocess Adapter Plugins (Feature F5 / ADR-008)

Dynamic Subprocess Adapter Plugins enable developers and organizations to integrate third-party coding agents (e.g., Devin, Codex CLI, Aider, custom enterprise agents) into Agent Control **without recompiling or modifying the `agentcontrold` binary**.

External adapters run as independent child processes communicating with the daemon over standard streams (`stdin` and `stdout`) using a newline-delimited JSON (NDJSON / JSON-RPC) protocol.

### 3.1 Overview & Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    agentcontrold                            │
│               (CompositeAdapterFactory)                     │
└──────────────┬───────────────────────────────▲──────────────┘
               │ stdin: NDJSON Commands        │ stdout: NDJSON Events
               │ (Start, Input, Respond, etc.) │ (Ready, Output, Prompt, etc.)
               ▼                               │ stderr: Tail ring buffer
┌──────────────────────────────────────────────┴──────────────┐
│           SubprocessAdapter (plugin.rs)                     │
│  - Landlock LSM Sandboxing (pre-exec ruleset restriction)   │
│  - Keyring & D-Bus isolation (DBUS_SESSION_BUS_ADDRESS)     │
│  - Ambient auth variable stripping (AMBIENT_AUTH_ENV)       │
│  - SubprocessDropGuard (RAII task abort & SIGKILL)          │
│  - Stderr tail capture (20-line crash context buffer)       │
└──────────────────────────────┬──────────────────────────────┘
                               │ fork / exec
                               ▼
┌─────────────────────────────────────────────────────────────┐
│             External Plugin Executable                      │
│        (e.g., devin-adapter, my-agent-cli)                  │
└─────────────────────────────────────────────────────────────┘
```

The daemon orchestrates external plugins via `SubprocessAdapter` (`crates/ac-core/src/adapter/plugin.rs`):
- Spawns the configured executable as a child process with piped stdin, stdout, and stderr.
- Spawns dedicated asynchronous Tokio tasks:
  - `cmd_task`: Serializes incoming `AgentCommand` instances to NDJSON lines over child stdin.
  - `stdout_task`: Consumes NDJSON lines from child stdout, converting them to `AdapterEvent` payloads with automatic plaintext fallback.
  - `stderr_task`: Captures stderr lines into an in-memory 20-line ring buffer for post-crash diagnostics and forwards them as high-confidence output events.
  - `monitor_task`: Awaits child process completion, emitting `AdapterEvent::Completed` on exit code 0 or `AdapterEvent::Crashed` with exit code and recent stderr diagnostics on non-zero exit.
- Guarantees clean resource reclamation using RAII via `SubprocessDropGuard`.

---

### 3.2 TOML Configuration Schema

Plugin adapters are configured in `config.toml` under the `[[plugins]]` array. Multiple plugins can be defined simultaneously:

```toml
# config.toml

[[plugins]]
# Unique identifier for the plugin
name = "devin-adapter"

# Path or command name of the executable binary (searched in PATH if relative)
executable = "/usr/local/bin/devin-adapter"

# Arguments passed to the executable upon spawning
args = ["--mode", "daemon", "--log-level", "info"]

# Environment variables injected directly into the child process
[plugins.env]
DEVIN_REGION = "us-west-2"
DEVIN_API_TIMEOUT = "120"

# Agent types routed to this plugin (must be unique across all plugins)
agent_types = ["devin", "cognition"]

# Declared capabilities of the plugin adapter
[plugins.capabilities]
# Account switching mode: "dynamic", "requires_restart", or "unsupported"
switch_mode = "dynamic"

# Whether the agent supports resuming existing sessions
supports_session_resume = true

# Whether the agent can restore state from a SessionSnapshot
supports_snapshot_restore = true

# Whether switching accounts requires restarting the subprocess
requires_process_restart = false

# Whether the plugin supports pseudo-terminal execution
supports_pty = false

# Whether the plugin supports automatic approval of safe actions
supports_auto_accept = true

# Model names advertised by this adapter
models = ["devin-v1", "devin-fast"]
```

#### Field Reference

| Section | Field | Type | Required | Description |
|---|---|---|---|---|
| `[[plugins]]` | `name` | String | Yes | Unique name identifying the plugin adapter. |
| `[[plugins]]` | `executable` | Path / String | Yes | Path to the binary or script. If relative, resolved against `PATH`. Must have executable permissions (`0o111`). |
| `[[plugins]]` | `args` | List of Strings | No | CLI arguments passed to the binary (default: `[]`). |
| `[[plugins]]` | `env` | Table (Map) | No | Custom environment variables injected into the child process. |
| `[[plugins]]` | `agent_types` | List of Strings | Yes | Agent type identifiers routed to this plugin (e.g., `["devin", "cognition"]`). Must contain at least one non-empty string. |
| `[plugins.capabilities]` | `switch_mode` | String | No | Account switching model: `"dynamic"`, `"requires_restart"` (default), or `"unsupported"`. Alias: `account_switch_mode`. |
| `[plugins.capabilities]` | `supports_session_resume` | Boolean | No | Whether the adapter can resume previous session IDs (default: `false`). |
| `[plugins.capabilities]` | `supports_snapshot_restore` | Boolean | No | Whether the adapter can restore state from snapshots (default: `false`). |
| `[plugins.capabilities]` | `requires_process_restart` | Boolean | No | Process restart required on credential update (default: `true`). |
| `[plugins.capabilities]` | `supports_pty` | Boolean | No | Terminal PTY support (default: `false`). |
| `[plugins.capabilities]` | `supports_auto_accept` | Boolean | No | Safe auto-approval support (default: `false`). |
| `[plugins.capabilities]` | `models` | List of Strings | No | List of supported model identifiers (default: `[]`). |

Validation rules enforced at daemon startup:
- Plugin `name` cannot be empty.
- Plugin `executable` cannot be empty and must exist with execute permissions.
- Plugin `agent_types` must not be empty.
- Plugin names must be unique across the configuration.
- Agent types must not collide across different plugins.

---

### 3.3 NDJSON / JSON-RPC Communication Protocol

Communication between `agentcontrold` and the adapter subprocess is stream-based via single-line JSON objects terminated by `\n` (NDJSON).

#### 3.3.1 Inbound Stdin Commands (Daemon → Adapter Subprocess)

The daemon emits commands to the child process standard input:

| Command | JSON Payload Format | Description |
|---|---|---|
| `Start` | `{"Start":{"session_id":"...","task_description":"...","agent_type":"..."}}` | Sent automatically upon child process launch with session context. |
| `Input` | `{"Input":{"data":"..."}}` | Raw text or stdin payload sent to the agent. |
| `Respond` | `{"Respond":{"allow":true,"response":"Optional user response"}}` | Human approval or question reply answering a pending prompt. |
| `Steer` | `{"Steer":{"message":"..."}}` | Mid-flight steering instruction directed to the agent. |
| `Resize` | `{"Resize":{"rows":24,"cols":80}}` | Terminal window dimension updates (if PTY is supported). |
| `Pause` | `{"Pause":{}}` or `{"Pause":null}` | Instructs the agent to pause execution. (Daemon also sends `SIGSTOP` on Unix). |
| `Resume` | `{"Resume":{}}` or `{"Resume":null}` | Instructs the agent to resume execution. (Daemon also sends `SIGCONT` on Unix). |
| `Stop` | `{"Stop":{"reason":"Optional shutdown reason"}}` | Requests graceful agent shutdown. (Daemon follows with `SIGTERM` and `SIGKILL` timeout). |
| `Snapshot` | `{"Snapshot":{}}` or `{"Snapshot":null}` | Requests the agent to produce a state snapshot for hand-off. |
| `SwitchAccount` | `{"SwitchAccount":{"credential_ref":"ref:account:..."}}` | Dynamic in-flight account credential rotation. |

#### 3.3.2 Outbound Stdout Events (Adapter Subprocess → Daemon)

The adapter subprocess writes events to its standard output. The parser supports both native Serde-tagged event schemas and simplified type-tagged JSON schemas:

| Event Type | Simplified JSON Schema | Native Serde Tagged Schema | Description |
|---|---|---|---|
| `Ready` | `{"type":"ready"}` or `{"type":"started"}` | `"Ready"` | Indicates agent initialization is complete. Note: Emitted automatically on the first output event if omitted. |
| `OutputChunk` | `{"type":"output","text":"...","confidence":"high"}` (or `"data"`, `"output_chunk"`) | `{"OutputChunk":{"text":"...","confidence":"high"}}` | Streamed output text chunks. `confidence` can be `"high"` or `"low"`. |
| `ApprovalRequested` | `{"type":"approval_requested","tool_name":"git","prompt":"Run git push?"}` | `{"ApprovalRequested":{"tool_name":"git","prompt":"..."}}` | Halts execution requesting human confirmation for a specific tool action. |
| `QuestionRaised` | `{"type":"question_raised","prompt":"Which database port?"}` | `{"QuestionRaised":{"prompt":"..."}}` | Halts execution requesting a freeform answer from the user. |
| `Prompt` (Universal) | `{"type":"prompt","tool_name":"bash","message":"..."}` → `ApprovalRequested`<br>`{"type":"prompt","message":"..."}` → `QuestionRaised` | — | Convenience alias: maps to approval when `tool_name` is present, or question when absent. |
| `RateLimitSignal` | `{"type":"rate_limit","back_off_secs":60}` or `{"type":"rate_limit_signal",...}` | `{"RateLimitSignal":{"back_off_secs":60}}` | Signals upstream provider rate limiting with optional back-off duration in seconds. |
| `Paused` | `{"type":"paused"}` | `"Paused"` | Confirms session execution has paused. |
| `Resumed` | `{"type":"resumed"}` | `"Resumed"` | Confirms session execution has resumed. |
| `Completed` | `{"type":"completed","summary":"Task done"}` or `{"type":"stopped",...}` | `{"Completed":{"summary":"..."}}` | Signals normal task completion. |
| `Crashed` | `{"type":"crashed","exit_code":1,"reason":"Out of memory"}` or `{"type":"failed",...}`, `{"type":"error",...}` | `{"Crashed":{"exit_code":1,"reason":"..."}}` | Signals abnormal agent failure with exit code and reason. |
| `SnapshotProduced` | `{"type":"snapshot_produced","summary":"State saved"}` | `{"SnapshotProduced":{"summary":"..."}}` | Emits snapshot metadata produced during session hand-off. |
| `StartFailed` | `{"type":"start_failed","reason":"Missing dependencies"}` | `{"StartFailed":{"reason":"..."}}` | Signals initialization failure before session start. |

#### 3.3.3 Plaintext Fallback

If an external adapter outputs standard unstructured plaintext instead of formatted JSON lines (for example, compiler output, raw logs, or legacy CLI output), `SubprocessAdapter` automatically captures each line and wraps it into an `AdapterEvent::OutputChunk` with low confidence:

```json
{"OutputChunk":{"text":"Compiling target v1.0.0...","confidence":"low"}}
```

This guarantees that external scripts and legacy CLI tools stream visible output without crashing the parser or swallowing logs.

#### 3.3.4 Stderr Monitoring & Diagnostic Ring Buffer

- Every line written to standard error (`stderr`) by the child process is intercepted by `stderr_task`.
- Stderr lines are logged as warnings in the daemon tracing system (`warn!("plugin [{}] stderr: {}", ...)`) and forwarded to the event stream as `[stderr] <message>` output chunks with high confidence.
- The most recent 20 lines of stderr are retained in an in-memory ring buffer (`VecDeque<String>`). If the subprocess crashes or exits with a non-zero exit status, the captured stderr tail is automatically appended to the `reason` field of `AdapterEvent::Crashed`:

```
Plugin 'devin-adapter' process exited with status exit status: 1 - recent stderr:
Traceback (most recent call last):
  File "adapter.py", line 42, in <module>
    raise ConnectionResetError("API gateway disconnected")
```

---

### 3.4 Process Lifecycle, Drop Guard & Linux Landlock Sandboxing

#### 3.4.1 Process Lifecycle Management

1. **Preflight**:
   - Validates that the configured workspace directory exists and is a directory.
   - Validates that the configured `executable` binary exists and has execute permissions (`0o111`).
2. **Spawning**:
   - Resolves executable against system `PATH` if not absolute.
   - Sets working directory to `workspace_path`.
   - Neutralizes ambient host credentials and D-Bus keyring interception.
   - Applies pre-exec Linux Landlock sandboxing ruleset.
   - Spawns child process with piped stdio and immediately transmits initial `AgentCommand::Start`.
3. **Execution & Supervision**:
   - Asynchronous Tokio tasks handle bidirectional NDJSON translation.
   - `Pause` and `Resume` commands combine NDJSON event dispatch with Unix `SIGSTOP` and `SIGCONT` signals.
4. **Graceful Stop**:
   - `AgentCommand::Stop` transmits a `{"Stop":{}}` command over stdin and sends `SIGTERM` to the child PID.
   - The daemon allows a 500ms grace window for clean shutdown before escalating to `SIGKILL`.
5. **Drop Guard (`SubprocessDropGuard`)**:
   - `SubprocessAdapter` implements an RAII drop guard wrapping the child process.
   - If the adapter handle is dropped (e.g., daemon shutdown, session cancellation, or unhandled panic), `SubprocessDropGuard`:
     1. Aborts all background Tokio tasks (`cmd_task`, `stdout_task`, `stderr_task`, `monitor_task`).
     2. Checks if the child process has already exited via an atomic flag (`exited: Arc<AtomicBool>`).
     3. If the process is still running, immediately invokes `libc::kill(pid, SIGKILL)` on Unix.
   - Guarantees zero orphaned background processes or leaked child tasks.

#### 3.4.2 Kernel-Enforced Filesystem Sandboxing (Linux Landlock)

`SubprocessAdapter` seamlessly integrates with Agent Control's Linux Landlock filesystem isolation engine (Feature F4):
- **Pre-Fork Ruleset Compilation**: The parent daemon compiles the Landlock ruleset based on `SessionContext`:
  - **Read-Write**: Designated `workspace_path`, isolated account profile (`~/.config/agentcontrol/profiles/<account-id>/`), `/tmp`, `/dev` (supporting `/dev/null` redirection), and configured extra write paths.
  - **Read-Only**: Essential system binaries and dynamic libraries (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`, `/etc`, `/proc`, `/sys`).
  - **Restricted**: User home directory outside profile, `~/.ssh`, `~/.aws`, `~/.gnupg`, outside repositories strictly return `EACCES` (Permission Denied).
- **Zero-Allocation Child Restriction**: The compiled Landlock ruleset file descriptor is passed to `tokio::process::Command::pre_exec`, enforcing `prctl(PR_SET_NO_NEW_PRIVS, 1)` and `landlock_restrict_self` before executing the plugin binary.
- On non-Linux platforms or Linux kernels without Landlock support (pre-5.13), the adapter gracefully falls back without failure.

#### 3.4.3 Environment Isolation & Variable Injection

To prevent credential leakage and environment cross-contamination:
- **Ambient Auth Variable Stripping**: All ambient variables defined in `AMBIENT_AUTH_ENV` (e.g., `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, etc.) are stripped from the child environment.
- **Keyring Neutralization**: `DBUS_SESSION_BUS_ADDRESS="disabled:"` is injected to block unauthorized access to desktop credential managers (GNOME Keyring, KWallet) over D-Bus.
- **Context Injection**: The daemon automatically injects standard context variables into the child environment:
  - `AC_SESSION_ID`: Monotonic UUID of the active session.
  - `AC_AGENT_TYPE`: Agent type identifier routed to the adapter.
  - `AC_TASK_DESCRIPTION` / `AC_TASK`: Text prompt describing the assigned task.
  - `AC_WORKSPACE_PATH` / `AC_WORKSPACE`: Canonical path to the session workspace.
  - `AC_ACCOUNT_ID`: UUID of the selected account (if assigned).
  - `AC_CREDENTIAL_REF`: Safe indirect credential reference (e.g. `ref:account:agy_123`).
  - Custom environment variables defined in `[plugins.env]`.

---

### 3.5 Example External Adapter Script

Here is an example production-ready external adapter implemented in Python (`devin_adapter.py`). It demonstrates reading stdin commands, emitting structured NDJSON events, asking for human approval, and handling clean shutdowns:

```python
#!/usr/bin/env python3
"""
Example Dynamic Subprocess Adapter Plugin for Agent Control.
Communicates with agentcontrold over stdin/stdout using NDJSON.
"""

import sys
import json
import os
import time

def send_event(event_obj):
    """Write a single NDJSON line to stdout and flush immediately."""
    sys.stdout.write(json.dumps(event_obj) + "\n")
    sys.stdout.flush()

def log_stderr(message):
    """Write diagnostic messages to stderr for monitoring."""
    sys.stderr.write(f"[adapter] {message}\n")
    sys.stderr.flush()

def main():
    log_stderr("Devin adapter plugin initialized")
    
    # Read environment variables injected by agentcontrold
    session_id = os.environ.get("AC_SESSION_ID", "unknown")
    workspace = os.environ.get("AC_WORKSPACE_PATH", ".")
    task = os.environ.get("AC_TASK_DESCRIPTION", "No task provided")
    
    # Emit ready event
    send_event({"type": "ready"})
    send_event({
        "type": "output",
        "text": f"Starting session {session_id} in {workspace}...\n",
        "confidence": "high"
    })

    # Process loop consuming NDJSON commands from stdin
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
            
        try:
            cmd = json.loads(line)
        except json.JSONDecodeError:
            log_stderr(f"Malformed command: {line}")
            continue

        # Handle Start command
        if "Start" in cmd:
            task_desc = cmd["Start"].get("task_description", task)
            send_event({
                "type": "output",
                "text": f"Task received: {task_desc}\nAnalyzing workspace...\n",
                "confidence": "high"
            })
            
            # Request human approval before executing a sensitive action
            send_event({
                "type": "approval_requested",
                "tool_name": "bash",
                "prompt": "Execute 'git fetch && git rebase origin/main'?"
            })

        # Handle Respond command (human approval / question answer)
        elif "Respond" in cmd:
            allow = cmd["Respond"].get("allow", False)
            response = cmd["Respond"].get("response")
            
            if allow:
                send_event({
                    "type": "output",
                    "text": "Action approved by operator. Running rebase...\n",
                    "confidence": "high"
                })
                time.sleep(0.5)
                send_event({
                    "type": "completed",
                    "summary": "Workspace rebase completed successfully."
                })
                break
            else:
                send_event({
                    "type": "output",
                    "text": f"Action rejected: {response or 'No reason provided'}.\n",
                    "confidence": "high"
                })
                send_event({
                    "type": "completed",
                    "summary": "Task cancelled by operator."
                })
                break

        # Handle Steer command
        elif "Steer" in cmd:
            message = cmd["Steer"].get("message", "")
            send_event({
                "type": "output",
                "text": f"Steering received: {message}\n",
                "confidence": "high"
            })

        # Handle Stop command
        elif "Stop" in cmd:
            reason = cmd["Stop"].get("reason", "Operator requested stop")
            log_stderr(f"Shutting down: {reason}")
            send_event({
                "type": "completed",
                "summary": f"Stopped: {reason}"
            })
            break

    log_stderr("Devin adapter exiting cleanly")

if __name__ == "__main__":
    main()
```

---

## 4. In-Tree Adapter Development (Compiled Adapters)

To add support for a new coding agent (e.g. `codex-cli` or `devin`):

### Step 1: Implement the `AdapterFactory` Trait

In `crates/ac-core/src/adapter/<agent_name>.rs`:

```rust
use anyhow::Result;
use tokio::sync::mpsc;
use crate::types::{AdapterEvent, ProviderCapabilities, SessionContext};
use crate::adapter::{AdapterFactory, AdapterHandle};

pub struct CustomAgentFactory;

impl AdapterFactory for CustomAgentFactory {
    fn capabilities(&self, agent_type: &str) -> ProviderCapabilities {
        ProviderCapabilities {
            supports_pty: true,
            supports_auto_accept: true,
            models: vec!["default".to_string()],
        }
    }

    fn preflight(&self, ctx: &SessionContext) -> Result<()> {
        // Validate credentials, binary paths, or project workspace
        Ok(())
    }

    fn create(
        &mut self,
        ctx: SessionContext,
        event_tx: mpsc::Sender<AdapterEvent>,
    ) -> Result<AdapterHandle> {
        // 1. Prepare child process command and environment
        // 2. Allocate PTY or pipe channels
        // 3. Spawn background reader task to send AdapterEvent::Output
        // 4. Return AdapterHandle with drop guard
        todo!()
    }
}
```

### Step 2: Register in `CompositeAdapterFactory`

In `crates/ac-core/src/adapter/mod.rs`, add your new factory to the routing match in `CompositeAdapterFactory::create()`:

```rust
match ctx.agent_type.as_str() {
    "antigravity" | "agy" => self.pty_factory.create(ctx, event_tx),
    "claude-code" => self.claude_factory.create(ctx, event_tx),
    "custom-agent" => self.custom_factory.create(ctx, event_tx),
    _ => Err(anyhow::anyhow!("Unknown agent type: {}", ctx.agent_type)),
}
```

### Step 3: Add End-to-End Tests

Add an integration test in `crates/ac-cli/tests/` to verify session startup, output streaming, and termination under real or mock environments.
