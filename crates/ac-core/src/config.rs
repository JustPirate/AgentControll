//! Daemon configuration loaded from a TOML file.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::types::{AccountSwitchMode, ProviderCapabilities};

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
    /// Kernel-enforced filesystem sandboxing configuration (Feature F4).
    #[serde(default)]
    pub sandbox: SandboxConfig,
    /// Dynamic subprocess adapter plugins (Feature F5 / ADR-008).
    #[serde(default)]
    pub plugins: Vec<PluginConfig>,
    /// Account pool and auto-failover configuration.
    #[serde(default)]
    pub accounts: AccountsConfig,
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
            sandbox: SandboxConfig::default(),
            plugins: Vec::new(),
            accounts: AccountsConfig::default(),
        }
    }
}

/// Configuration for account management and failover behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountsConfig {
    pub auto_failover: AutoFailoverConfig,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            auto_failover: AutoFailoverConfig::default(),
        }
    }
}

/// Configuration for autonomous quota failover and 429 auto-handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoFailoverConfig {
    /// Whether autonomous quota failover is enabled (default: true).
    pub enabled: bool,
    /// Default cooldown period in seconds for rate-limited accounts (default: 60).
    pub default_cooldown_secs: u64,
}

impl Default for AutoFailoverConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_cooldown_secs: 60,
        }
    }
}

/// Configuration for kernel-enforced filesystem sandboxing (Feature F4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Whether sandboxing is enabled by default (default: true on Linux).
    pub enabled: bool,
    /// Sandboxing enforcement mode: "auto", "landlock", or "disabled".
    pub mode: String,
    /// Whether outbound network access is permitted (default: true).
    pub allow_network: bool,
    /// Extra paths granted Read-Only access.
    pub extra_read_paths: Vec<PathBuf>,
    /// Extra paths granted Read-Write access.
    pub extra_write_paths: Vec<PathBuf>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: cfg!(target_os = "linux"),
            mode: "auto".to_string(),
            allow_network: true,
            extra_read_paths: Vec::new(),
            extra_write_paths: Vec::new(),
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

/// Configuration for a dynamic subprocess adapter plugin (Feature F5 / ADR-008).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Unique identifier for this plugin (e.g. "devin-adapter", "custom-coder").
    pub name: String,
    /// Path or command name of the executable binary.
    pub executable: PathBuf,
    /// Arguments to pass when spawning the plugin subprocess.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variables injected into the plugin subprocess.
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// Agent types routed to this plugin (e.g. ["devin", "cognition"]).
    #[serde(default)]
    pub agent_types: Vec<String>,
    /// Declared capabilities of the plugin adapter.
    #[serde(default)]
    pub capabilities: PluginCapabilitiesConfig,
}

impl PluginConfig {
    pub fn new(
        name: impl Into<String>,
        executable: impl Into<PathBuf>,
        agent_types: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            executable: executable.into(),
            args: Vec::new(),
            env: HashMap::new(),
            agent_types,
            capabilities: PluginCapabilitiesConfig::default(),
        }
    }

    pub fn with_arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn with_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn with_env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    pub fn with_agent_type(mut self, agent_type: impl Into<String>) -> Self {
        self.agent_types.push(agent_type.into());
        self
    }

    pub fn with_capabilities(mut self, capabilities: PluginCapabilitiesConfig) -> Self {
        self.capabilities = capabilities;
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            anyhow::bail!("plugin name cannot be empty");
        }
        if self.executable.as_os_str().is_empty() {
            anyhow::bail!("plugin '{}' executable cannot be empty", self.name);
        }
        if self.agent_types.is_empty() {
            anyhow::bail!(
                "plugin '{}' must specify at least one agent_type",
                self.name
            );
        }
        for at in &self.agent_types {
            if at.trim().is_empty() {
                anyhow::bail!("plugin '{}' contains an empty agent_type", self.name);
            }
        }
        Ok(())
    }
}

/// Declared capabilities for a dynamic subprocess adapter plugin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PluginCapabilitiesConfig {
    /// Account switching mode: "dynamic", "requires_restart", or "unsupported".
    #[serde(alias = "account_switch_mode")]
    pub switch_mode: AccountSwitchMode,
    /// Whether the agent can resume a prior session context.
    pub supports_session_resume: bool,
    /// Whether the agent can restore state from a SessionSnapshot.
    pub supports_snapshot_restore: bool,
    /// Whether changing accounts requires restarting the underlying process.
    pub requires_process_restart: bool,
    /// Whether the plugin supports pseudo-terminal execution.
    pub supports_pty: bool,
    /// Whether the plugin supports automatic approval of safe actions.
    pub supports_auto_accept: bool,
    /// List of model names supported by the agent.
    pub models: Vec<String>,
}

impl Default for PluginCapabilitiesConfig {
    fn default() -> Self {
        Self {
            switch_mode: AccountSwitchMode::RequiresRestart,
            supports_session_resume: false,
            supports_snapshot_restore: false,
            requires_process_restart: true,
            supports_pty: false,
            supports_auto_accept: false,
            models: Vec::new(),
        }
    }
}

impl PluginCapabilitiesConfig {
    pub fn to_provider_capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            switch_mode: self.switch_mode,
            supports_session_resume: self.supports_session_resume,
            supports_snapshot_restore: self.supports_snapshot_restore,
            requires_process_restart: self.requires_process_restart
                || matches!(self.switch_mode, AccountSwitchMode::RequiresRestart),
        }
    }
}

impl From<&PluginCapabilitiesConfig> for ProviderCapabilities {
    fn from(cfg: &PluginCapabilitiesConfig) -> Self {
        cfg.to_provider_capabilities()
    }
}

impl From<PluginCapabilitiesConfig> for ProviderCapabilities {
    fn from(cfg: PluginCapabilitiesConfig) -> Self {
        cfg.to_provider_capabilities()
    }
}

impl Config {
    /// Validate all registered plugins for duplicate names or conflicting agent_types.
    pub fn validate_plugins(&self) -> Result<()> {
        let mut seen_names = HashSet::new();
        let mut seen_agent_types = HashMap::new();

        for plugin in &self.plugins {
            plugin.validate()?;

            if !seen_names.insert(&plugin.name) {
                anyhow::bail!("duplicate plugin name: '{}'", plugin.name);
            }

            for at in &plugin.agent_types {
                if let Some(prev_plugin) = seen_agent_types.insert(at, &plugin.name) {
                    anyhow::bail!(
                        "conflicting agent_type '{}': declared in both '{}' and '{}'",
                        at,
                        prev_plugin,
                        plugin.name
                    );
                }
            }
        }
        Ok(())
    }

    /// Validate configuration invariants.
    pub fn validate(&self) -> Result<()> {
        self.validate_plugins()?;
        Ok(())
    }
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
        cfg.validate()?;
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
    fn test_default_accounts_and_auto_failover_config() {
        let cfg = Config::default();
        assert!(cfg.accounts.auto_failover.enabled);
        assert_eq!(cfg.accounts.auto_failover.default_cooldown_secs, 60);
    }

    #[test]
    fn test_accounts_config_toml_parsing() {
        let toml_str = r#"
db_path = "/tmp/test.db"
socket_path = "/tmp/test.sock"

[accounts.auto_failover]
enabled = false
default_cooldown_secs = 120
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse accounts toml");
        assert!(!cfg.accounts.auto_failover.enabled);
        assert_eq!(cfg.accounts.auto_failover.default_cooldown_secs, 120);
    }

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

    #[test]
    fn test_sandbox_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.sandbox.enabled, cfg!(target_os = "linux"));
        assert_eq!(cfg.sandbox.mode, "auto");
        assert!(cfg.sandbox.allow_network);
        assert!(cfg.sandbox.extra_read_paths.is_empty());
        assert!(cfg.sandbox.extra_write_paths.is_empty());
    }

    #[test]
    fn test_sandbox_config_toml_parsing() {
        let toml_str = r#"
db_path = "/tmp/test.db"
socket_path = "/tmp/test.sock"

[sandbox]
enabled = true
mode = "landlock"
allow_network = false
extra_read_paths = ["/opt/models", "/srv/data"]
extra_write_paths = ["/var/log/custom"]
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse toml");
        assert!(cfg.sandbox.enabled);
        assert_eq!(cfg.sandbox.mode, "landlock");
        assert!(!cfg.sandbox.allow_network);
        assert_eq!(
            cfg.sandbox.extra_read_paths,
            vec![PathBuf::from("/opt/models"), PathBuf::from("/srv/data")]
        );
        assert_eq!(
            cfg.sandbox.extra_write_paths,
            vec![PathBuf::from("/var/log/custom")]
        );
    }

    #[test]
    fn test_plugin_config_toml_parsing_full() {
        let toml_str = r#"
db_path = "/tmp/test.db"
socket_path = "/tmp/test.sock"

[[plugins]]
name = "devin-adapter"
executable = "/usr/local/bin/devin-adapter"
args = ["--mode", "daemon", "--verbose"]
agent_types = ["devin", "cognition"]

[plugins.env]
DEV_API_KEY = "test-key"
CUSTOM_VAR = "custom-val"

[plugins.capabilities]
switch_mode = "dynamic"
supports_session_resume = true
supports_snapshot_restore = true
requires_process_restart = false
supports_pty = true
supports_auto_accept = true
models = ["devin-default", "devin-fast"]
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse toml with plugins");
        assert_eq!(cfg.plugins.len(), 1);
        let p = &cfg.plugins[0];
        assert_eq!(p.name, "devin-adapter");
        assert_eq!(p.executable, PathBuf::from("/usr/local/bin/devin-adapter"));
        assert_eq!(p.args, vec!["--mode", "daemon", "--verbose"]);
        assert_eq!(p.agent_types, vec!["devin", "cognition"]);
        assert_eq!(p.env.get("DEV_API_KEY").map(String::as_str), Some("test-key"));
        assert_eq!(p.env.get("CUSTOM_VAR").map(String::as_str), Some("custom-val"));
        assert_eq!(p.capabilities.switch_mode, AccountSwitchMode::Dynamic);
        assert!(p.capabilities.supports_session_resume);
        assert!(p.capabilities.supports_snapshot_restore);
        assert!(!p.capabilities.requires_process_restart);
        assert!(p.capabilities.supports_pty);
        assert!(p.capabilities.supports_auto_accept);
        assert_eq!(p.capabilities.models, vec!["devin-default", "devin-fast"]);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_plugin_config_toml_parsing_defaults() {
        let toml_str = r#"
db_path = "/tmp/test.db"
socket_path = "/tmp/test.sock"

[[plugins]]
name = "minimal-plugin"
executable = "minimal-bin"
agent_types = ["minimal"]
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse toml");
        assert_eq!(cfg.plugins.len(), 1);
        let p = &cfg.plugins[0];
        assert_eq!(p.name, "minimal-plugin");
        assert_eq!(p.executable, PathBuf::from("minimal-bin"));
        assert!(p.args.is_empty());
        assert!(p.env.is_empty());
        assert_eq!(p.agent_types, vec!["minimal"]);
        assert_eq!(
            p.capabilities.switch_mode,
            AccountSwitchMode::RequiresRestart
        );
        assert!(!p.capabilities.supports_session_resume);
        assert!(!p.capabilities.supports_snapshot_restore);
        assert!(p.capabilities.requires_process_restart);
        assert!(!p.capabilities.supports_pty);
        assert!(!p.capabilities.supports_auto_accept);
        assert!(p.capabilities.models.is_empty());

        let prov_caps: ProviderCapabilities = (&p.capabilities).into();
        assert_eq!(prov_caps.switch_mode, AccountSwitchMode::RequiresRestart);
        assert!(!prov_caps.supports_session_resume);
        assert!(!prov_caps.supports_snapshot_restore);
        assert!(prov_caps.requires_process_restart);
    }

    #[test]
    fn test_plugin_capabilities_conversion() {
        let cap_cfg = PluginCapabilitiesConfig {
            switch_mode: AccountSwitchMode::Dynamic,
            supports_session_resume: true,
            supports_snapshot_restore: false,
            requires_process_restart: false,
            supports_pty: true,
            supports_auto_accept: true,
            models: vec!["gpt-4".into()],
        };
        let prov_caps = cap_cfg.to_provider_capabilities();
        assert_eq!(prov_caps.switch_mode, AccountSwitchMode::Dynamic);
        assert!(prov_caps.supports_session_resume);
        assert!(!prov_caps.supports_snapshot_restore);
        assert!(!prov_caps.requires_process_restart);

        let from_ref: ProviderCapabilities = (&cap_cfg).into();
        assert_eq!(from_ref, prov_caps);

        let from_val: ProviderCapabilities = cap_cfg.into();
        assert_eq!(from_val, prov_caps);
    }

    #[test]
    fn test_plugin_validation_errors() {
        // Empty name
        let p1 = PluginConfig::new("", "bin", vec!["type1".into()]);
        assert!(p1.validate().is_err());
        let p1_ws = PluginConfig::new("   ", "bin", vec!["type1".into()]);
        assert!(p1_ws.validate().is_err());

        // Empty executable
        let p2 = PluginConfig::new("p2", "", vec!["type1".into()]);
        assert!(p2.validate().is_err());

        // Empty agent types
        let p3 = PluginConfig::new("p3", "bin", vec![]);
        assert!(p3.validate().is_err());

        // Agent types with empty string
        let p4 = PluginConfig::new("p4", "bin", vec!["   ".into()]);
        assert!(p4.validate().is_err());

        // Valid plugin
        let p5 = PluginConfig::new("p5", "bin", vec!["valid".into()]);
        assert!(p5.validate().is_ok());
    }

    #[test]
    fn test_config_validation_duplicate_plugin_name() {
        let mut cfg = Config::default();
        cfg.plugins = vec![
            PluginConfig::new("plugin-a", "bin1", vec!["type-a".into()]),
            PluginConfig::new("plugin-a", "bin2", vec!["type-b".into()]),
        ];
        let err = cfg.validate().unwrap_err();
        assert!(err.to_string().contains("duplicate plugin name: 'plugin-a'"));
    }

    #[test]
    fn test_config_validation_conflicting_agent_types() {
        let mut cfg = Config::default();
        cfg.plugins = vec![
            PluginConfig::new("plugin-a", "bin1", vec!["shared-type".into()]),
            PluginConfig::new("plugin-b", "bin2", vec!["shared-type".into()]),
        ];
        let err = cfg.validate().unwrap_err();
        assert!(err
            .to_string()
            .contains("conflicting agent_type 'shared-type'"));
    }

    #[test]
    fn test_plugin_config_builder() {
        let plugin = PluginConfig::new("my-plugin", "/bin/my-plugin", vec!["type1".into()])
            .with_arg("--foo")
            .with_args(vec!["--bar", "baz"])
            .with_env("KEY1", "VAL1")
            .with_agent_type("type2")
            .with_capabilities(PluginCapabilitiesConfig {
                switch_mode: AccountSwitchMode::Dynamic,
                ..Default::default()
            });

        assert_eq!(plugin.name, "my-plugin");
        assert_eq!(plugin.executable, PathBuf::from("/bin/my-plugin"));
        assert_eq!(plugin.args, vec!["--foo", "--bar", "baz"]);
        assert_eq!(plugin.env.get("KEY1").map(String::as_str), Some("VAL1"));
        assert_eq!(plugin.agent_types, vec!["type1", "type2"]);
        assert_eq!(plugin.capabilities.switch_mode, AccountSwitchMode::Dynamic);
        assert!(plugin.validate().is_ok());
    }
}

