# Configuration Guide

Agent Control operates with zero required configuration out of the box, using sensible defaults following the XDG Base Directory specification. For custom deployments, behavior can be customized using a TOML configuration file and environment variables.

---

## Configuration File Location

The background daemon (`agentcontrold`) searches for its configuration file in the following order:

1. **`$AC_CONFIG`** environment variable (if set).
2. **`$XDG_CONFIG_HOME/agentcontrol/config.toml`** (typically `~/.config/agentcontrol/config.toml`).
3. If no file exists, internal defaults are used automatically.

### Example `config.toml`

```toml
# Path to SQLite event store
db_path = "~/.local/share/agentcontrol/events.db"

# Path to Unix domain socket for IPC communication
socket_path = "/run/user/1000/agentcontrol.sock"

# Maximum restart attempts before marking a crashed session as Failed
max_restarts = 3

# Base exponential backoff delay (in milliseconds) for session restarts
restart_backoff_base_ms = 1000

# Daemon logging level: "error", "warn", "info", "debug", "trace"
log_level = "info"

# WebSocket server toggle (loopback only)
ws_enabled = true

# Loopback bind address for WebSocket API
ws_bind_addr = "127.0.0.1:4242"

# Optional path to token file for WebSocket authentication (<token>:<scope>)
# ws_auth_token_path = "~/.config/agentcontrol/ws_tokens.txt"

# Notification & Webhook Configuration (Feature F8)
[notifications]
# Master switch to enable notification dispatching (default: false)
enabled = true

# Discord incoming webhook URL for rich embeds with color-coded alerts
# discord_webhook_url = "https://discord.com/api/webhooks/..."

# Slack incoming webhook URL for colored message attachments
# slack_webhook_url = "https://hooks.slack.com/services/..."

# Generic HTTP webhook URLs receiving standard JSON event payloads
generic_webhook_urls = [
    # "https://example.com/api/webhooks/agentcontrol"
]

# Enable local desktop notifications (notify-send on Linux, osascript on macOS)
desktop_notifications = false

# Subscribed event triggers
events = [
    "session_crashed",
    "human_intervention_required",
    "quota_exhausted",
    "session_finished",
    "session_stopped",
]

# Webhook request and notification process timeout in milliseconds
timeout_ms = 5000

# Maximum retries on 5xx server responses or transient network failures
max_retries = 2
```

---

## Notifications & Webhooks Configuration

AgentControll includes an asynchronous, non-blocking notification dispatcher subsystem (Feature F8) running inside `agentcontrold`. The system pushes alerts on critical session lifecycle and account events to external destinations:

- **Discord**: Formats rich embeds with color coding (red for crash/failure, yellow for human intervention/rate limits, green for completion/stop, blue for tests/informational), session ID, agent type, error message / details, and ISO-8601 timestamps.
- **Slack**: Formats incoming webhook payloads with colored attachments and structured fields.
- **Generic Webhooks**: Delivers standard JSON payloads (`{ "event": ..., "timestamp": ..., "session_id": ..., "payload": ... }`) to arbitrary HTTP endpoints with exponential backoff retries on 5xx errors.
- **Desktop Notifications**: Dispatches non-blocking notifications locally via `notify-send` on Linux (with urgency levels `-u critical`, `-u normal`, `-u low`) and `osascript` on macOS.

### Notification Configuration Keys

- `enabled` (Boolean, default: `false`): Master switch enabling the notification dispatcher background task. When false and no webhook URLs are provided, dispatcher tasks remain dormant. If environment variables `AC_DISCORD_WEBHOOK` or `AC_SLACK_WEBHOOK` are detected, notification dispatch is automatically promoted to active.
- `discord_webhook_url` (Option<String>, default: `None`): Target URL for incoming Discord webhooks.
- `slack_webhook_url` (Option<String>, default: `None`): Target URL for incoming Slack webhooks.
- `generic_webhook_urls` (Array of Strings, default: `[]`): List of HTTP/HTTPS endpoints receiving raw event payloads.
- `desktop_notifications` (Boolean, default: `false`): Enables local desktop notifications. Safely handles headless displays or missing binaries without failing.
- `events` (Array of Strings, default: `["session_crashed", "human_intervention_required", "quota_exhausted", "session_finished", "session_stopped"]`): Subscribed event kinds or trigger aliases. Events not matching this filter are dropped before dispatch.
- `timeout_ms` (Integer, default: `5000`): Maximum time in milliseconds to wait for HTTP responses or desktop subprocess completion before timing out.
- `max_retries` (Integer, default: `2`): Number of exponential backoff retry attempts on 5xx HTTP responses or transient network errors. 4xx client errors are rejected immediately without retry.

### Environment Variable Overrides

Webhook endpoints can also be configured dynamically via environment variables without editing `config.toml`:

- **`AC_DISCORD_WEBHOOK`**: Overrides `notifications.discord_webhook_url` and automatically enables notification dispatching.
- **`AC_SLACK_WEBHOOK`**: Overrides `notifications.slack_webhook_url` and automatically enables notification dispatching.

---

## Settings Reference

| Key | Type | Default | Description |
|:---|:---|:---|:---|
| `db_path` | String (Path) | `~/.local/share/agentcontrol/events.db` | SQLite event store database file path. |
| `socket_path` | String (Path) | `$XDG_RUNTIME_DIR/agentcontrol.sock` | POSIX Unix domain socket used for IPC between CLI/TUI and daemon. |
| `max_restarts` | Integer | `3` | Number of restart attempts before a crashing agent enters `Failed` state. |
| `restart_backoff_base_ms` | Integer | `1000` | Starting delay in ms for exponential backoff on crashes. |
| `log_level` | String | `"info"` | Tracing level filter (`error`, `warn`, `info`, `debug`, `trace`). |
| `ws_enabled` | Boolean | `true` | Enables loopback WebSocket server for real-time telemetry streaming. |
| `ws_bind_addr` | String | `"127.0.0.1:4242"` | IP and port for the WebSocket server (strictly loopback `127.0.0.1`). |
| `ws_auth_token_path` | String (Path) | `None` | Path to optional file containing `<token>:<scope>` pairs for token auth. |
| `notifications.enabled` | Boolean | `false` | Master toggle for external notification and webhook dispatch. |
| `notifications.discord_webhook_url` | String (URL) | `None` | Discord webhook URL for rich embed alerts with color coding. |
| `notifications.slack_webhook_url` | String (URL) | `None` | Slack incoming webhook URL for colored message attachments. |
| `notifications.generic_webhook_urls` | List of Strings | `[]` | List of generic HTTP endpoints receiving JSON event payloads. |
| `notifications.desktop_notifications` | Boolean | `false` | Enables local desktop notifications (`notify-send` / `osascript`). |
| `notifications.events` | List of Strings | `["session_crashed", ...]` | Events that trigger alerts. |
| `notifications.timeout_ms` | Integer | `5000` | HTTP request and subprocess timeout in milliseconds. |
| `notifications.max_retries` | Integer | `2` | Maximum retry attempts for failed webhook requests on 5xx errors. |

---

## Environment Variables

| Variable | Default | Purpose |
|:---|:---|:---|
| `AC_CONFIG` | None | Overrides the path to `config.toml`. |
| `AC_LOG` | Config `log_level` | Tracing filter string for daemon output (e.g. `debug,ac_core::pty=trace`). |
| `RUST_LOG` | `"info"` | Fallback tracing filter if `AC_LOG` is unset. |
| `AC_DISCORD_WEBHOOK` | None | Overrides `notifications.discord_webhook_url` and enables notification dispatching. |
| `AC_SLACK_WEBHOOK` | None | Overrides `notifications.slack_webhook_url` and enables notification dispatching. |
| `AGENTCONTROL_BIN_DIR` | None | Override directory path to look for prebuilt binaries before downloading. |
| `XDG_CONFIG_HOME` | `~/.config` | Base path for configuration files and profile credentials. |
| `XDG_DATA_HOME` | `~/.local/share` | Base path for persistent SQLite event databases. |
| `XDG_RUNTIME_DIR` | `/tmp` | Directory for POSIX domain sockets (`mode 0600`). |

---

## Precedence Order

When resolving configuration options, Agent Control applies precedence in the following descending order:

1. **CLI Flags** (e.g., `--socket <path>`, `--log-level <level>`)
2. **Environment Variables** (e.g., `AC_LOG`, `AC_CONFIG`, `AC_DISCORD_WEBHOOK`, `AC_SLACK_WEBHOOK`)
3. **Configuration File** (`config.toml`)
4. **Built-in Defaults**
