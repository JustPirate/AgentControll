# agentcontroll

**Local-first control plane for coding agents (Antigravity, Claude Code, Codex, Devin CLI)**

`agentcontroll` manages, sandboxes, switches between, and monitors autonomous coding agents inside full-fidelity terminal sessions with hardware-isolated account profiles, kernel-enforced Landlock sandboxing, cryptographic audit log signing, token budget tracking, priority task queuing, autonomous 429 quota failover, and zero-configuration launch flows.

## Quick Start

You can run AgentControll without manual compilation using `npx`:

```bash
npx agentcontroll
```

Or install it globally:

```bash
npm install -g agentcontroll
agentcontroll
```

On first execution, the runner detects your host operating system and CPU architecture, downloads the matching prebuilt release binary, and invokes the terminal interface with transparent signal and stdio forwarding.

## Key Capabilities

- **Autonomous Quota Failover (429 Auto-Handoff):** Detects 429 rate limits and quota exhaustion across Claude Code, Subprocess Plugins, and Antigravity PTY sessions. Places exhausted accounts into timed cooldown and automatically hands off to the lowest-load backup account without human intervention.
- **Cryptographic Audit Log Signing (ADR-010):** Canonical SHA-256 hash chaining on all events stored in SQLite v2 (`ac audit verify`).
- **Cost Accounting & Spending Budgets (F6):** Token usage tracking and multi-provider pricing engine with hard/soft budget enforcement (`ac cost`, `ac budget`).
- **Continuous Session Task Backlog Queue (F11):** Persistent task backlog queue in `queue.db` with priority scheduling and autonomous successor chaining (`ac queue`).
- **Kernel-Enforced Filesystem Sandboxing (F4):** Unprivileged Linux Landlock filesystem confinement restricting agents strictly to their assigned workspace.
- **Dynamic Subprocess Adapter Plugins (ADR-008):** Declarative TOML plugin support for arbitrary CLI agents (e.g. Devin CLI, Cognition, custom tools).
- **Built-in Virtual Terminal Emulator (`TerminalBuffer`):** TrueColor ANSI rendering, distraction-free fullscreen (`Ctrl+F`), non-destructive cursor navigation, mouse drag selection, regex scrollback search (`/`), URL picker (`o`), visual mode (`v`), and OSC 52 clipboard sync.

## Commands

The package includes the standard suite of commands:

```bash
# Launch the interactive terminal UI
agentcontroll

# Shorthand alias
ac

# Session management
ac session list
ac session create --task "Fix bug" --agent-type claude

# Continuous task backlog queue
ac queue add --title "Refactor module" --priority high
ac queue list

# Cost accounting & spending budgets
ac cost
ac budget set daily 25.00

# Cryptographic audit log verification
ac audit verify

# Reusable session templates
ac template list
ac template run default

# Diagnose installation health, credentials, and account switching isolation
agentcontroll doctor
# or
ac doctor

# Deep diagnostics (scans for orphan profiles and unreferenced credentials)
agentcontroll doctor --deep

# Machine-readable JSON output
agentcontroll doctor --json

# Inspect daemon state or start the background control daemon
agentcontrold --help
```

> **Note on Antigravity (`agy`):** AgentControll manages external Antigravity sessions and credentials, but does **not** install, wrap, or replace the external Google Antigravity CLI (`agy`). The real `agy` executable must be installed separately on your system.

## Supported Systems

- **Linux x86_64** (glibc 2.31+)
- **macOS x86_64** (Intel)
- **macOS aarch64** (Apple Silicon)
- **Windows**: Run natively inside [WSL2](https://learn.microsoft.com/en-us/windows/wsl/install) (`npx agentcontroll`)

## License

MIT © AgentControll contributors. See [LICENSE](https://github.com/vijaygovindBiju/AgentControll/blob/main/LICENSE) for details.
