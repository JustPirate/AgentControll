# Changelog

All notable changes to AgentControll are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Dynamic Subprocess Adapter Plugins (F5 / ADR-008)**: Out-of-process dynamic agent adapter framework enabling third-party coding agents (e.g., Devin, Codex CLI, custom enterprise agents) to integrate into `agentcontrold` without daemon recompilation via standard NDJSON / JSON-RPC streams (`feat(adapter): dynamic subprocess adapter plugins via NDJSON/JSON-RPC`).
  - **Subprocess Adapter Engine (`crates/ac-core/src/adapter/plugin.rs`)**: Implemented `SubprocessAdapter` orchestrating external executable lifecycles over standard I/O pipes. Spawns dedicated background Tokio tasks for stdin command dispatch (`cmd_task`), stdout event ingestion (`stdout_task`), stderr tail monitoring (`stderr_task`), and exit status observation (`monitor_task`).
  - **TOML Configuration Schema (`crates/ac-core/src/config.rs`)**: Added `PluginConfig` and `PluginCapabilitiesConfig` loaded via `[[plugins]]` array in `config.toml`. Supports executable path resolution against system `PATH`, command arguments, custom environment variables, routed `agent_types`, and granular capabilities (`switch_mode`, `supports_session_resume`, `supports_snapshot_restore`, `requires_process_restart`, `supports_pty`, `supports_auto_accept`, `models`) with validation preventing duplicate names or colliding agent types.
  - **Bidirectional NDJSON / JSON-RPC Protocol**: Full translation between internal daemon commands (`Start`, `Input`, `Respond`, `Steer`, `Resize`, `Pause`, `Resume`, `Stop`, `Snapshot`, `SwitchAccount`) and NDJSON payloads. Ingests native Serde-tagged events and simplified JSON schemas (`ready`/`started`, `output`/`output_chunk`, `approval_requested`/`prompt`, `question_raised`, `rate_limit_signal`, `completed`/`stopped`, `crashed`/`failed`, `snapshot_produced`, `start_failed`).
  - **Plaintext Fallback & Diagnostic Stderr Ring Buffer**: Automatically converts unformatted legacy CLI plaintext into low-confidence `OutputChunk` events. Captures stderr into an in-memory 20-line ring buffer (`stderr_tail`) emitted as high-confidence output and appended to `Crashed` event diagnostic reasons on abnormal process termination.
  - **Process Lifecycle & RAII Drop Guard**: Implemented `SubprocessDropGuard` guaranteeing child task abortion and Unix `SIGKILL` escalation on adapter drop to prevent orphaned processes. Implemented Unix `SIGSTOP` / `SIGCONT` signaling for pause and resume, and a 500ms `SIGTERM`-to-`SIGKILL` graceful shutdown window on stop.
  - **Security Isolation & Linux Landlock Sandboxing**: Integrated kernel-enforced filesystem sandboxing (Feature F4) applying pre-exec Landlock rulesets (`PR_SET_NO_NEW_PRIVS`, `landlock_restrict_self`), workspace boundary enforcement, host D-Bus keyring neutralization (`DBUS_SESSION_BUS_ADDRESS="disabled:"`), ambient credential stripping (`AMBIENT_AUTH_ENV`), and safe context environment injection (`AC_SESSION_ID`, `AC_AGENT_TYPE`, `AC_WORKSPACE_PATH`, etc.).
  - **Composite Adapter Factory Routing (`crates/ac-core/src/adapter/mod.rs`)**: Wired dynamic plugin registry into `CompositeAdapterFactory`, dynamically dispatching `capabilities()`, `preflight()`, and `create()` to configured plugin executables by matching `agent_type`.
  - **Integration Test Suite (`crates/ac-core/tests/plugin_adapter_tests.rs`)**: 10 comprehensive integration tests verifying TOML deserialization, validation errors, composite routing, normal lifecycle, interactive approval prompts and responses, plaintext fallback, graceful stop, drop guard SIGKILL termination, crash detection with stderr capture, and Landlock/workspace boundary isolation with mock executable scripts.
- **Kernel-Enforced Filesystem Sandboxing (F4)**: Defense-in-depth Linux Security Module (Landlock) filesystem isolation for agent child processes (Antigravity, Claude Code, Shell, and generic PTY sessions), neutralizing Threat T6 (workspace boundary violation).
  - **Linux Landlock Sandboxing Engine (`crates/ac-core/src/sandbox.rs`)**: Direct Linux syscalls (`SYS_landlock_create_ruleset`, `SYS_landlock_add_rule`, `SYS_landlock_restrict_self`) and `prctl(PR_SET_NO_NEW_PRIVS)`. Automatic runtime probing of kernel Landlock ABI versions (v1–v4) with graceful fallback on older kernels and non-Linux OSes.
  - **Pre-Fork Ruleset Compilation Pattern**: Compiles rulesets and registers `O_PATH` path allowlists in the parent process before fork. Child process `pre_exec` restriction calls only async-signal-safe syscalls (`prctl`, `landlock_restrict_self`, `close`) with zero memory allocations and zero mutexes.
  - **Filesystem Boundary Policy**: Read-Write access granted exclusively to designated `workspace_path`, isolated account profile (`~/.config/agentcontrol/profiles/<account-id>/`), `/tmp`, `/dev` (so standard redirection to `/dev/null` works), and configured extra write paths. Read-Only access granted to standard system binaries and dynamic linker files (`/usr`, `/lib`, `/lib64`, `/bin`, `/sbin`, `/opt`, `/etc`, `/proc`, `/sys`). All other paths (user home directory outside profile, `~/.ssh`, `~/.aws`, `~/.gnupg`, outside repositories) strictly return `EACCES` (Permission Denied).
  - **Regular File Mask Invariant**: Automatically applies `FILE_MASK` (`EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE`) to regular files when adding path rules, avoiding kernel `EINVAL` on directory-only flags.
  - **Adapter & Process Integration**: Integrated into `crates/ac-core/src/adapter/claude.rs` (structured NDJSON child process via `tokio::process::Command::pre_exec`) and `crates/ac-core/src/adapter/pty.rs` (PTY sessions via slave pts device handle and `std::process::Command::pre_exec`), preserving PTY terminal I/O, resizing, and streaming.
  - **Configuration & Policy**: Added `[sandbox]` configuration section to `Config` with `enabled` (default `true` on Linux), `mode` (`"auto"`, `"landlock"`, `"disabled"`), `allow_network`, `extra_read_paths`, and `extra_write_paths`.
  - **Diagnostics & Doctor**: Added `system.landlock` diagnostic check to `ac doctor` reporting kernel Landlock ABI version and sandbox readiness.
  - **CLI Flags**: Added `--sandbox` and `--no-sandbox` flags to `ac session create` and `ac session run`.
  - **Integration Test Suite**: Added `crates/ac-core/tests/sandbox_tests.rs` with child subprocess isolation verifying ABI probe, workspace read/write vs outside path `EACCES` rejection, profile isolation, Claude structured sandboxing, and PTY sandboxed execution.
- **Webhook & External Notification Triggers (F8)**: Asynchronous, non-blocking notification and webhook dispatch system in `agentcontrold` triggering alerts on critical session lifecycle and account events (`SessionCrashed`, `HumanInterventionRequired`, `QuotaExhausted`, `SessionStopped`, `SessionFinished`).
  - **Notification Dispatcher Engine**: Event-driven dispatcher running as an independent background task subscribed to `AgentEvent` broadcast streams with trigger filtering, delivery metrics tracking, timeout enforcement, and exponential backoff retry handling on 5xx errors.
  - **Discord Webhooks**: Rich embed formatter with color coding (red for crash/failure, yellow for intervention/rate limit, green for completion/stop, blue for test/info), session ID, agent type, timestamp, and error details.
  - **Slack Webhooks**: Incoming webhook payload formatter with colored attachments and structured fields.
  - **Generic HTTP Webhooks**: Configurable endpoints receiving standard JSON payloads (`{ "event", "timestamp", "session_id", "payload" }`) with timeout and exponential retry handling.
  - **Local Desktop Notifications**: Asynchronous desktop alert delivery using `notify-send` on Linux and `osascript` on macOS with urgency levels and timeout protection, resilient against headless displays.
  - **Configuration & Environment Variables**: Configured via `[notifications]` in `config.toml` and overridden by `AC_DISCORD_WEBHOOK` and `AC_SLACK_WEBHOOK`.
  - **IPC & WebSocket Support**: `notification.test` and `notification.status` endpoints with token scope mutation enforcement.
  - **CLI Subcommand**: Added `ac notify test` / `ac notification test` and `ac notify status` / `ac notification status` commands with pretty table and scriptable plain (`--plain`) formatting modes, and client RPC methods in `DaemonClient`.

## [1.1.0] - 2026-11-18

### Added
- **Native Metrics & OpenTelemetry Export (F12)**: Embedded Prometheus 0.0.4 exporter, HTTP health endpoints, IPC metrics API, and CLI telemetry commands for monitoring agent sessions and daemon health.
  - **Metrics Engine & Collector**: Implemented `MetricsCollector` in `crates/ac-core/src/metrics.rs` collecting telemetry from `SessionManager`, `InteractionHub`, `AccountManager`, and SQLite `EventStore`. Tracks sessions total, active states breakdown, crash and restart counts, session duration histogram, interaction outcomes by decision, pending interaction count, approval latency histogram, account provider counts, and concurrency caps.
  - **Prometheus 0.0.4 & JSON Exporter**: Output formatted in standard Prometheus 0.0.4 text format with `# HELP` and `# TYPE` headers, strict label escaping (`"`, `\`, `\n`), and structured JSON representation.
  - **Lightweight HTTP Server**: Embedded asynchronous Tokio TCP server serving `GET /metrics` (`200 OK text/plain; version=0.0.4`) and Kubernetes liveness probes `GET /health` and `GET /livez` (`200 OK application/json`).
  - **Daemon Lifecycle & Config**: Added `metrics_enabled` (default: `true`) and `metrics_bind_addr` (default: `"127.0.0.1:9100"`) to `Config`. Integrated server lifecycle into `agentcontrold` with clean shutdown on SIGINT/SIGTERM.
  - **IPC & WebSocket Dispatch**: Handled `metrics.get` in `dispatch_request_ext` returning Prometheus text format and structured JSON metrics.
  - **CLI Telemetry Subcommand**: Added `ac metrics` command outputting standard Prometheus text format by default, or pretty-printed JSON with `--json`. Added `DaemonClient::get_metrics` in `client.rs`.
  - **Integration Test Suite**: Added comprehensive tests in `crates/ac-core/tests/metrics_tests.rs` covering HTTP scraping, health endpoints, IPC dispatch, Prometheus syntax compliance, and dynamic counter increments.
- **Claude Code Multi-Account Isolation (ADR-014)**: Full per-account profile and credential isolation for Claude Code sessions.
  - **Isolated Profile Environments**: Created isolated profile directories under `~/.config/agentcontrol/profiles/<account-id>/` with restricted filesystem permissions (`0700` directories, `0600` config files), private `.claude` directories, and symlinked developer tooling excluding configuration targets (`crates/ac-core/src/adapter/claude.rs`).
  - **Keyring & D-Bus Disconnection**: Enforced `DBUS_SESSION_BUS_ADDRESS="disabled:"` across child processes to isolate Claude CLI / keytar from host desktop keyrings (GNOME Keyring / KWallet).
  - **Ambient Credential Wiping**: Automatically stripped ambient authentication environment variables (`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_API_KEY`, etc.) preventing host environment credential leakage.
  - **Anthropic Credential Routing**: Added support for storing and resolving Anthropic API keys (`apiKey`) and raw secrets through `credentials.rs`, injecting them safely into child process environment and isolated `~/.claude.json`.
  - **Integration Testing**: Authored comprehensive test suite `claude_multi_account_tests.rs` verifying account registration, zero-bleed process isolation, concurrent multi-account execution, and profile cleanup.
- **Reusable Session Templates & Presets (F10)**: End-to-end framework for saving, managing, and instantiating standardized agent configurations across core daemon, IPC, CLI, and TUI.
  - **Persistent SQLite Storage & Manager**: Added `TemplateStore` and `TemplateManager` with WAL mode (`templates.db`), providing slug-validated CRUD operations, unique name constraints, and in-memory caching (`crates/ac-core/src/template_manager.rs`).
  - **IPC & WebSocket Template API**: Introduced `template.create`, `template.list`, `template.get`, `template.delete` / `template.remove`, `template.update`, and `session.create_from_template` endpoints with token scope enforcement (`crates/ac-core/src/ipc.rs`, `crates/ac-core/src/ws.rs`).
  - **CLI Template Management Suite**: Added `ac template` command family (`list`, `create`, `get`, `delete`, `run`) with table, scriptable plain (`--plain`), and JSON (`--json`) output modes. Extended `ac session run` with `--template <NAME>` support (`crates/ac-cli/src/bin/ac.rs`, `crates/ac-cli/src/client.rs`).
  - **Interactive TUI Template Selector**: Integrated template cycling and task prompt editing into `StartSessionForm`, auto-populating account, permission mode, model, and launch options with wrap-around navigation (`crates/ac-tui/src/launch.rs`, `crates/ac-tui/src/views/start_session.rs`).
  - **Comprehensive Test Suite**: Added 87 end-to-end CLI template tests (`crates/ac-cli/tests/template_e2e_tests.rs`), IPC lifecycle and token-scope tests (`crates/ac-core/tests/template_tests.rs`), and TUI modal interaction tests (`crates/ac-tui/tests/start_session_tests.rs`).

## [1.0.13] - 2026-11-17

### Fixed
- **Daemon Graceful Shutdown & Socket Cleanup**: Handled SIGTERM alongside SIGINT in `agentcontrold` using `tokio::select!`. IPC socket file is now guaranteed to be cleaned up on graceful shutdown or process termination, preventing stale socket errors on restart (resolves #2).
- **Session Resumption for Stopped & Crashed Sessions**: Allowed `session.resume` in `SessionManager` and the state machine to restart sessions in `Stopped` and `Crashed` states with their preserved launch configuration, workspace, and account context (resolves #1).
- **TUI Session Re-run Navigation**: Pressing `Space` to re-run a stopped or crashed session automatically focuses and navigates the session detail view to the newly started session.

### Added
- **CLI Conversation Resumption**: Added `-c` / `--conversation <ID>` flags to `ac session create` and `ac session run` to launch or resume specific Antigravity conversations.
- **On-Demand Conversation Inspection**: Added `ac conversation list` and `ac session discover` commands to discover and inspect existing Antigravity conversations across host (`~/.gemini/`) and account profile storage without polluting the active session list.
- **TUI Conversation Resume Field**: Added an optional "Resume Conversation ID" input field to `StartSessionForm` in the New Session modal.

## [1.0.12] - 2026-10-24

### Changed
- Removed automatic Antigravity conversation discovery from daemon startup and TUI refresh. Existing Antigravity conversations are no longer imported into the Sessions list.
- Removed the session discovery command from IPC and the CLI.

## [1.0.11] - 2026-10-22

### Fixed
- **Resume conversations created outside AgentControll**: Import the selected conversation's summary index entry into the isolated account profile along with its trajectory database, allowing Antigravity to resolve and resume external conversations.
- Preserve the host Antigravity history and existing profile conversations during the import.

## [1.0.10] - 2026-10-22

### Added
- **Cross-device Antigravity sign-in**: Added a QR-enabled browser portal, support for completing sign-in from another device, and a pasted OAuth redirect fallback in the CLI and TUI.
- **Antigravity conversation discovery and resume**: Discover local conversations from host and isolated account profiles, display them in the Sessions view, and resume a selected conversation with its account and workspace context.
- **Terminal themes**: Added 13 color palettes and applied selected theme colors throughout TUI tabs and dialogs.

### Changed
- Improved Antigravity account login guidance and documented cross-device and headless login flows.
- Updated release and install examples to version 1.0.10.

## [1.0.9] - 2026-10-10

### Added
- **Configurable Keybindings**: Introduced customizable keybindings across the TUI with persistence in user settings (`KeybindingsConfig`). Users can view, rebind via interactive modal key-capture, or reset bindings to default for actions including detach, fullscreen toggle, split pane focus, command palette, URL picker, session steer, resume, and account switching.
- **Interactive Shell Agent Providers**: Added native support for `shell`, `bash`, and `zsh` agent types within the composite adapter factory to run standard shell sessions alongside coding agents.
- **Scriptable Plain CLI Output**: Added `--plain` (`-p`) flag to `ac` CLI for clean, tab-delimited output without decorative headers or borders, automatically enabled when stdout is redirected to non-terminal unix pipes.
- **OSC 52 Clipboard Integration**: Supported OSC 52 ANSI clipboard escape sequences in `TerminalBuffer` with automatic base64 decoding and system clipboard synchronization.

### Changed
- Refactored settings view into an interactive multi-tab configuration interface with real-time keybinding remapping.

## [1.0.8] - 2026-10-08

### Fixed
- **Terminal buffer input and PTY dimension synchronization**: Fixed visual artifacts and ghost prompt text when running interactive agent CLIs (such as Antigravity `agy` running Bubbletea).
  - Dynamically allocated PTY instances with the user's actual terminal dimensions (`initial_rows`, `initial_cols`) from frame 0 rather than hardcoded 24×80, preventing startup banners (such as `dismiss` tags) from wrapping and detaching.
  - Synchronized internal virtual terminal dimensions (`app.resize_session_terminals`) immediately upon entering session views from Dashboard and Sessions tabs.
  - Enhanced trailing blank space detection (`is_blank_trailing_space`) in `TerminalBuffer` to ensure styled spaces emitted by CLI backspace/erase sequences (`\x08 \x08`) properly wipe erased characters without leaving stale ghost text on the screen.

### Added
- Automated unit and regression tests for frame-0 PTY dimension allocation and styled trailing space prompt erasure.

## [1.0.7] - 2026-10-07

### Fixed
- **Antigravity (`agy`) account switching isolation from host desktop keyrings**: Fixed an issue where `agy` would bypass its isolated profile token and authenticate as the host machine's primary desktop account on Linux. Injected `DBUS_SESSION_BUS_ADDRESS="disabled:"` into child `agy` process environments to neutralize D-Bus Secret Service lookups, forcing `agy` to source authentication exclusively from its profile token file (`~/.config/agentcontrol/profiles/<id>/.gemini/antigravity-cli/antigravity-oauth-token`).
- **System diagnostics (`ac doctor`)**: Added `env.keyring_isolation` diagnostic check to verify that host D-Bus keyring interception is blocked on child process sessions.

## [1.0.6] - 2026-10-07

### Fixed
- **Account selection bug in TUI launch form**: Fixed a bug where the persisted `default_account` setting would override the currently selected account in the UI. When users selected a different account in the Accounts tab and pressed `n` to start a new session, the form would incorrectly use the stale default account instead of the user's current selection. The fix prioritizes the currently selected account from the UI, using the persisted default only as a fallback when no account is selected.

## [1.0.0] - 2026-09-22

Initial production-ready release of AgentControll — the multi-account supervision and orchestration daemon for coding agents.


### Highlights

- **Seamless Multi-Account Agent Switching**: Run multiple accounts across providers (e.g., Anthropic Claude Code, OpenAI, Generic PTY CLI tools) and switch identities without manual logout/login cycles.
- **Controlled Process Hand-Off**: Versioned session snapshots allow transitioning running agents between accounts with preserved project workspaces and execution metadata.
- **Autonomous Policy Engine & Approval Inbox**: Declarative rule evaluation with a hardcoded never-auto-approve boundary for destructive commands (`rm`, `sudo`, `curl | sh`, `force push`).
- **Unified Transports**: Full parity between local Unix Domain Socket IPC and authenticated WebSocket loopback (`ws://127.0.0.1:4242`).
- **Granular Token Scopes**: Strict capability isolation (`read`, `write`, `admin`) preventing read-only telemetry clients from mutating daemon state.
- **High-Performance Event Sourcing**: Append-only SQLite WAL store achieving >72,000 events/sec batch ingestion and sub-second recovery of 10,000 sessions from 100,000 events.
- **Terminal User Interface (TUI)**: Full-screen interactive dashboard built with Ratatui and Crossterm, featuring live event streaming, modal approval/question answering, and interactive account switching.

### Added

#### Phase 1 — Core Daemon & State Machine
- `AgentSession` state machine enforcing 10 lifecycle states (`Idle`, `Starting`, `Working`, `WaitingForHuman`, `Paused`, `RateLimited`, `Stopping`, `Stopped`, `Failed`, `Crashed`).
- SQLite append-only event store with sequential gap detection and monotonic IDs.
- Deterministic Mock adapter for offline lifecycle testing and crash back-off validation.
- CLI subcommands for session lifecycle management (`session.create`, `session.start`, `session.pause`, `session.resume`, `session.stop`).

#### Phase 2 — Account Manager & Project Registry
- Account registry supporting state transitions (`Active`, `Exhausted`, `Disabled`), tag filtering, and concurrency limits.
- Deterministic least-loaded account selection strategy with tie-breaking on account ID.
- Project and workspace registry supporting `Shared` and `WorktreePerSession` git workspace policies.

#### Phase 3 — Interaction Hub & Policy Engine
- Human-in-the-loop interaction hub managing approval requests, user questions, and notifications.
- Declarative policy rules with priority ordering and condition operators (`Equals`, `Contains`, `StartsWith`, `EndsWith`, `Regex`).
- Absolute `NeverAutoApprove` boundary enforcing mandatory human escalation for destructive filesystem and network operations.
- SQLite-backed audit log capturing all automated and human decisions.

#### Phase 4 — Real Agent Adapters
- Claude Code structured adapter consuming child-process NDJSON streaming events (`control_request`, `progress`, `text`).
- Generic PTY adapter using pseudo-terminal allocation (`portable-pty`) and regex pattern matching to interact with arbitrary CLI agents.
- Composite adapter factory routing sessions to appropriate backends by agent type.

#### Phase 5 — Terminal User Interface (TUI)
- Multi-tab Ratatui dashboard (`Sessions`, `Inbox`, `Accounts`, `Projects`, `Events`).
- Real-time event streaming and UI updating over local Unix domain sockets.
- Modal dialogs for human approval, freeform question replies, and interactive account switching.
- Comprehensive headless rendering test suite using `ratatui::backend::TestBackend`.

#### Phase 6 — Seamless Multi-Account Agent Switching
- Provider-neutral account switching abstraction distinguishing idle re-binding from active session hand-offs.
- Controlled session hand-off lifecycle (`AccountSwitchStarted`, `SessionSnapshotCreated`, `SessionHandOffCompleted`) preserving workspace and project context.
- Provider capabilities model declaring restart requirements and context preservation guarantees.
- Strict credential indirection (`env:<VAR>` or `ref:<ID>`), guaranteeing raw credentials never enter SQLite, events, audit records, errors, snapshots, or TUI displays.

#### Phase 7 — External API v1 & WebSocket Loopback
- Frozen Control API wire schema v1 with version mismatch rejection.
- Embedded authenticated WebSocket loopback server with `Authorization: Bearer <TOKEN>` or `x-agent-control-token` header parsing.
- Granular token authorization scopes (`read`, `write`, `admin`).
- Advanced subscription filtering by event kinds, `session_id`, `project_id`, and `account_id` with historical catch-up replay (`since_seq`).

#### Phase 8 — Hardening, Security Audit & Migration Tooling
- Automated security audit suite verifying threat models T1–T5 in `docs/SECURITY.md`:
  - T1: Zero credential leakage in snapshots, database columns, event queries, and API responses.
  - T2: Socket permissions (`0600`) and read-only token mutation prevention.
  - T3: Tamper-proof never-auto-approve boundary.
  - T4: Workspace directory traversal and escape containment.
  - T5: Malicious shell and SQL injection immunity in steer messages and task descriptions.
- Robustness and fuzz test suite verifying wire parsers against deeply nested JSON (500 levels), 2MB oversized payloads, malformed NDJSON, ANSI escapes, and ReDoS attacks.
- High-throughput batch ingestion (`EventStore::append_batch`) yielding >72,000 events/second.
- Performance benchmark demonstrating recovery of 10,000 sessions from 100,000 events in ~808 milliseconds (beating the < 5.0-second threshold).
- Diagnostic integrity and replay CLI subcommands (`ac event verify` and `ac event replay`).

#### User Experience Layer & Multi-Account UX
- Two-layer CLI architecture: `agentcontroll` and `agy` for normal developers, `ac` for power-user scripting and automation.
- `agy "Account Label"` direct launcher with automatic daemon spawning, friendly account label resolution, and interactive session attachment.
- Automatic interactive account selector for `agy` with cooldown tracking and concurrency limit displays.
- Automated OAuth 2.0 PKCE loopback authentication on `127.0.0.1:0` (`agy account add`) with manual code and pasted-redirect callback fallbacks.
- Secure `0600` credential file persistence (`~/.config/agentcontrol/credentials/agy_<id>.json`) referenced solely by `ref:antigravity:<id>`.

#### Post-v1 Hardening & Interactive Terminal Ergonomics
- Dedicated Agent Terminal view with full ANSI virtual screen buffer ([`terminal_buffer.rs`](crates/ac-tui/src/terminal_buffer.rs)) supporting alternate screen buffers (`1049h`/`1049l`), cursor positioning, scroll regions, and truecolor ANSI rendering.
- Multi-byte UTF-8 stream decoder (`decode_utf8_stream`) ensuring UTF-8 glyphs split across chunk boundaries are never corrupted into `U+FFFD`.
- Anti-deadlock PTY architecture: non-blocking `try_send` dispatch, 8KB burst read buffers, and 512-item per-session event queues eliminating reader thread deadlocks during large generation bursts.
- Transparent key forwarding: `Esc` is forwarded directly to the agent PTY (for vi/nano modes, dialog dismissals, and agy prompt interactions), while `Ctrl+Q` cleanly detaches back to the supervisor dashboard.
- Streamlined 6-tab navigation (`1: Dashboard`, `2: Sessions`, `3: Accounts`, `4: Activity`, `5: Agents`, `6: Settings`).
- Centralized Settings hub with 9 keyboard-navigable sections (General, Accounts, Projects & Workspaces, Agents, Models, Permissions, Authentication, Terminal, Security), persistent to `~/.config/agentcontrol/settings.json`.
- Decoupled Antigravity execution modes (`Default`, `Accept Edits`, `Plan`) from permission boundaries (`Normal`, `Dangerously Skip Permissions` with a strict confirmation modal).
- Interactive session launch modal (`n`) with shell-style `Tab` directory path completion and interactive filtering.
- Isolated account profiles (`~/.config/agentcontrol/profiles/<account-id>/`) with `HOME` redirection and ambient Google credential stripping.
