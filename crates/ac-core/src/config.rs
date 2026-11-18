//! Daemon configuration loaded from a TOML file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Path to the SQLite database file.
    pub db_path: PathBuf,
    /// Path for the Unix domain socket.
    pub socket_path: PathBuf,
    /// Maximum restart attempts before a session reaches Failed state.
    pub max_restarts: u32,
    /// Base back-off delay in milliseconds for restart attempts.
    pub restart_backoff_base_ms: u64,
    /// Log level: error, warn, info, debug, trace.
    pub log_level: String,
    /// Whether the loopback WebSocket server is enabled (Phase 7 / ADR-009).
    pub ws_enabled: bool,
    /// Loopback bind address for the WebSocket server (e.g. "127.0.0.1:4242").
    pub ws_bind_addr: String,
    /// Optional path to a file containing authentication tokens (one per line: `<token>:<scope>`).
    pub ws_auth_token_path: Option<PathBuf>,
    /// Whether the native Prometheus /metrics HTTP exporter is enabled (Feature F12).
    pub metrics_enabled: bool,
    /// Loopback bind address for the metrics HTTP exporter (e.g. "127.0.0.1:9100").
    pub metrics_bind_addr: String,
    /// Notification and webhook dispatch configuration (Feature F8).
    #[serde(default)]
    pub notifications: NotificationConfig,
}

impl Default for Config {
    fn default() -> Self {
        let base = dirs_base();
        Self {
            db_path: base.join("events.db"),
            socket_path: runtime_dir().join("agentcontrol.sock"),
            max_restarts: 3,
            restart_backoff_base_ms: 1000,
            log_level: "info".to_owned(),
            ws_enabled: true,
            ws_bind_addr: "127.0.0.1:4242".to_owned(),
            ws_auth_token_path: None,
            metrics_enabled: true,
            metrics_bind_addr: "127.0.0.1:9100".to_owned(),
            notifications: NotificationConfig::default(),
        }
    }
}

/// Configuration for external notifications and webhook alerts (Feature F8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NotificationConfig {
    /// Whether notifications are enabled.
    pub enabled: bool,
    /// Discord webhook URL for rich embed notifications.
    pub discord_webhook_url: Option<String>,
    /// Slack webhook URL for slack message attachments.
    pub slack_webhook_url: Option<String>,
    /// List of generic webhook URLs receiving JSON event payloads.
    pub generic_webhook_urls: Vec<String>,
    /// Whether desktop notifications (notify-send on Linux, osascript on macOS) are enabled.
    pub desktop_notifications: bool,
    /// List of event names or aliases that trigger notifications.
    pub events: Vec<String>,
    /// Timeout for HTTP requests and desktop notification processes in milliseconds.
    pub timeout_ms: u64,
    /// Maximum retry attempts for failed webhook requests on 5xx errors or network failures.
    pub max_retries: u32,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            discord_webhook_url: None,
            slack_webhook_url: None,
            generic_webhook_urls: Vec::new(),
            desktop_notifications: false,
            events: vec![
                "session_crashed".to_owned(),
                "human_intervention_required".to_owned(),
                "quota_exhausted".to_owned(),
                "session_finished".to_owned(),
            ],
            timeout_ms: 5000,
            max_retries: 2,
        }
    }
}

impl NotificationConfig {
    /// Returns true if notifications are enabled or any channel is configured.
    pub fn is_active(&self) -> bool {
        self.enabled
            || self.discord_webhook_url.is_some()
            || self.slack_webhook_url.is_some()
            || !self.generic_webhook_urls.is_empty()
            || self.desktop_notifications
    }
}

impl Config {
    /// Apply environment variable overrides for notification webhooks.
    ///
    /// Setting `AC_DISCORD_WEBHOOK` or `AC_SLACK_WEBHOOK` automatically
    /// sets the corresponding URL and enables notifications (`enabled = true`).
    pub fn apply_env_overrides(&mut self) {
        if let Ok(val) = std::env::var("AC_DISCORD_WEBHOOK")
            .or_else(|_| std::env::var("AC_DISCORD_WEBHOOK_URL"))
        {
            let val = val.trim();
            if !val.is_empty() {
                self.notifications.discord_webhook_url = Some(val.to_owned());
                self.notifications.enabled = true;
            }
        }
        if let Ok(val) = std::env::var("AC_SLACK_WEBHOOK")
            .or_else(|_| std::env::var("AC_SLACK_WEBHOOK_URL"))
        {
            let val = val.trim();
            if !val.is_empty() {
                self.notifications.slack_webhook_url = Some(val.to_owned());
                self.notifications.enabled = true;
            }
        }
        if let Ok(val) = std::env::var("AC_NOTIFICATION_ENABLED") {
            if let Ok(b) = val.trim().parse::<bool>() {
                self.notifications.enabled = b;
            }
        }
    }

    /// Load configuration from a TOML file, falling back to defaults for
    /// any missing fields, and applying environment variable overrides.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file: {}", path.display()))?;
        let mut cfg: Config = toml::from_str(&text)
            .with_context(|| format!("parsing config file: {}", path.display()))?;
        cfg.apply_env_overrides();
        Ok(cfg)
    }

    /// Load from path if it exists, otherwise return defaults, with
    /// environment variable overrides applied.
    pub fn load_or_default(path: &Path) -> Self {
        let mut cfg = if path.exists() {
            Self::load(path).unwrap_or_default()
        } else {
            Self::default()
        };
        cfg.apply_env_overrides();
        cfg
    }
}

fn dirs_base() -> PathBuf {
    // XDG_DATA_HOME or ~/.local/share/agentcontrol
    std::env::var("XDG_DATA_HOME")
        .map(|d| PathBuf::from(d).join("agentcontrol"))
        .unwrap_or_else(|_| {
            dirs_home()
                .join(".local")
                .join("share")
                .join("agentcontrol")
        })
}

fn runtime_dir() -> PathBuf {
    // XDG_RUNTIME_DIR or /tmp
    std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_notification_config() {
        let cfg = Config::default();
        assert!(!cfg.notifications.enabled);
        assert!(cfg.notifications.discord_webhook_url.is_none());
        assert!(cfg.notifications.slack_webhook_url.is_none());
        assert!(cfg.notifications.generic_webhook_urls.is_empty());
        assert!(!cfg.notifications.desktop_notifications);
        assert_eq!(cfg.notifications.timeout_ms, 5000);
        assert_eq!(cfg.notifications.max_retries, 2);
        assert_eq!(
            cfg.notifications.events,
            vec![
                "session_crashed",
                "human_intervention_required",
                "quota_exhausted",
                "session_finished"
            ]
        );
        assert!(!cfg.notifications.is_active());
    }

    #[test]
    fn test_notification_config_toml_parsing() {
        let toml_str = r#"
db_path = "/tmp/test.db"
socket_path = "/tmp/test.sock"

[notifications]
enabled = true
discord_webhook_url = "https://discord.com/api/webhooks/123/abc"
slack_webhook_url = "https://hooks.slack.com/services/T/B/X"
generic_webhook_urls = ["https://example.com/webhook1", "https://example.com/webhook2"]
desktop_notifications = true
events = ["session_crashed", "quota_exhausted"]
timeout_ms = 8000
max_retries = 3
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse toml");
        assert!(cfg.notifications.enabled);
        assert_eq!(
            cfg.notifications.discord_webhook_url.as_deref(),
            Some("https://discord.com/api/webhooks/123/abc")
        );
        assert_eq!(
            cfg.notifications.slack_webhook_url.as_deref(),
            Some("https://hooks.slack.com/services/T/B/X")
        );
        assert_eq!(cfg.notifications.generic_webhook_urls.len(), 2);
        assert!(cfg.notifications.desktop_notifications);
        assert_eq!(cfg.notifications.events, vec!["session_crashed", "quota_exhausted"]);
        assert_eq!(cfg.notifications.timeout_ms, 8000);
        assert_eq!(cfg.notifications.max_retries, 3);
        assert!(cfg.notifications.is_active());
    }

    #[test]
    fn test_notification_config_is_active() {
        let mut notif = NotificationConfig::default();
        assert!(!notif.is_active());

        notif.enabled = true;
        assert!(notif.is_active());
        notif.enabled = false;

        notif.discord_webhook_url = Some("https://discord.com/webhook".to_owned());
        assert!(notif.is_active());
        notif.discord_webhook_url = None;

        notif.slack_webhook_url = Some("https://hooks.slack.com/services/xxx".to_owned());
        assert!(notif.is_active());
        notif.slack_webhook_url = None;

        notif.generic_webhook_urls.push("https://example.com/hook".to_owned());
        assert!(notif.is_active());
        notif.generic_webhook_urls.clear();

        notif.desktop_notifications = true;
        assert!(notif.is_active());
    }

    #[test]
    fn test_env_overrides_application() {
        let mut cfg = Config::default();
        assert!(!cfg.notifications.enabled);
        assert!(cfg.notifications.discord_webhook_url.is_none());

        // Test environment overrides
        std::env::set_var("AC_DISCORD_WEBHOOK", "https://discord.com/api/webhooks/env_test");
        std::env::set_var("AC_SLACK_WEBHOOK", "https://hooks.slack.com/env_test");
        cfg.apply_env_overrides();

        assert!(cfg.notifications.enabled);
        assert_eq!(
            cfg.notifications.discord_webhook_url.as_deref(),
            Some("https://discord.com/api/webhooks/env_test")
        );
        assert_eq!(
            cfg.notifications.slack_webhook_url.as_deref(),
            Some("https://hooks.slack.com/env_test")
        );

        // Clean up env vars
        std::env::remove_var("AC_DISCORD_WEBHOOK");
        std::env::remove_var("AC_SLACK_WEBHOOK");
    }
}

