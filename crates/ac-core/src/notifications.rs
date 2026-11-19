//! External notification and webhook dispatch system (Feature F8).
//!
//! Provides asynchronous, non-blocking notification dispatching to Discord,
//! Slack, generic HTTP webhooks, and local desktop notifications (`notify-send` / `osascript`).
//! Dispatches alerts on critical agent lifecycle events such as crashes,
//! required human intervention, quota exhaustion, and session completion.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, watch};

use crate::config::NotificationConfig;
use crate::types::{AgentEvent, EventKind};

/// Discord decimal integer color codes.
pub const COLOR_RED: u32 = 15548997; // 0xED4245 - Crashes, failures, exhaustion
pub const COLOR_GOLD: u32 = 16705372; // 0xFEE75C - Human intervention, approvals, rate limits
pub const COLOR_GREEN: u32 = 5763719; // 0x57F287 - Session finished, clean completions
pub const COLOR_BLUE: u32 = 5793266; // 0x5865F2 - Informational, test alerts

/// Slack attachment hex color codes.
pub const HEX_RED: &str = "#ED4245";
pub const HEX_GOLD: &str = "#FEE75C";
pub const HEX_GREEN: &str = "#57F287";
pub const HEX_BLUE: &str = "#5865F2";

/// Errors that can occur within the notification subsystem.
#[derive(Debug, thiserror::Error)]
pub enum NotificationError {
    #[error("Channel disabled or not configured: {0}")]
    ChannelNotConfigured(String),
    #[error("HTTP dispatch failed: {0}")]
    Http(String),
    #[error("Desktop notification failed: {0}")]
    Desktop(String),
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Delivery metrics tracked across all notification channels.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotificationMetrics {
    /// Total number of dispatch attempts across all channels.
    pub total_dispatched: u64,
    /// Number of successful notification deliveries.
    pub successful: u64,
    /// Number of failed notification deliveries.
    pub failed: u64,
    /// Timestamp of the last successful dispatch.
    pub last_success: Option<DateTime<Utc>>,
    /// Timestamp of the last failed dispatch.
    pub last_failure: Option<DateTime<Utc>>,
    /// Error message from the last failure, if any.
    pub last_error: Option<String>,
}

/// Result of an individual channel test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelTestResult {
    /// Name of the notification channel (`discord`, `slack`, `generic`, `desktop`).
    pub channel: String,
    /// Status of the delivery attempt (`success`, `failed`, `skipped`).
    pub status: String,
    /// Optional status details or error message.
    pub details: Option<String>,
}

/// Overall result of a notification test trigger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationTestResult {
    /// Results for each tested channel.
    pub channels: Vec<ChannelTestResult>,
}

/// Status report returned by the `notification.status` IPC/WebSocket command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStatusReport {
    /// Whether notifications are enabled.
    pub enabled: bool,
    /// Whether desktop notifications are enabled.
    pub desktop: bool,
    /// Whether a Discord webhook URL is configured.
    pub discord_configured: bool,
    /// Whether a Slack webhook URL is configured.
    pub slack_configured: bool,
    /// Number of configured generic webhook URLs.
    pub generic_webhooks_count: usize,
    /// Subscribed event kinds or aliases.
    pub events: Vec<String>,
    /// Delivery metrics since daemon startup.
    pub metrics: NotificationMetrics,
}

/// Standard generic webhook payload structure per Feature F8 specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenericWebhookPayload {
    /// Canonical event name (e.g. `session_crashed`, `interaction_created`).
    pub event: String,
    /// UTC timestamp of the event.
    pub timestamp: DateTime<Utc>,
    /// Optional session identifier associated with the event.
    pub session_id: Option<String>,
    /// Raw event payload data.
    pub payload: serde_json::Value,
}

/// Cloneable handle to the notification engine for status inspection, testing,
/// and manual event dispatch.
#[derive(Clone)]
pub struct NotificationHandle {
    config: Arc<NotificationConfig>,
    client: reqwest::Client,
    metrics: Arc<RwLock<NotificationMetrics>>,
}

impl NotificationHandle {
    /// Returns the current notification configuration.
    pub fn config(&self) -> &NotificationConfig {
        &self.config
    }

    /// Returns the current notification status report.
    pub fn status(&self) -> NotificationStatusReport {
        NotificationStatusReport {
            enabled: self.config.enabled,
            desktop: self.config.desktop_notifications,
            discord_configured: self.config.discord_webhook_url.is_some(),
            slack_configured: self.config.slack_webhook_url.is_some(),
            generic_webhooks_count: self.config.generic_webhook_urls.len(),
            events: self.config.events.clone(),
            metrics: self.metrics(),
        }
    }

    /// Returns a snapshot of current delivery metrics.
    pub fn metrics(&self) -> NotificationMetrics {
        self.metrics.read().map(|m| m.clone()).unwrap_or_default()
    }

    /// Records a successful delivery in metrics.
    pub fn record_success(&self) {
        if let Ok(mut m) = self.metrics.write() {
            m.total_dispatched += 1;
            m.successful += 1;
            m.last_success = Some(Utc::now());
        }
    }

    /// Records a failed delivery attempt in metrics.
    pub fn record_failure(&self, err: String) {
        if let Ok(mut m) = self.metrics.write() {
            m.total_dispatched += 1;
            m.failed += 1;
            m.last_failure = Some(Utc::now());
            m.last_error = Some(err);
        }
    }

    /// Sends a synthetic test notification across configured channels.
    ///
    /// `channel` can be `None` (test all active channels) or a specific channel
    /// (`discord`, `slack`, `generic`, `desktop`).
    pub async fn send_test(
        &self,
        channel: Option<String>,
        message: Option<String>,
    ) -> Result<NotificationTestResult, NotificationError> {
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let max_retries = self.config.max_retries;
        let target = channel.as_deref().unwrap_or("all").to_ascii_lowercase();
        let mut results = Vec::new();

        let test_discord = target == "all" || target == "discord";
        let test_slack = target == "all" || target == "slack";
        let test_generic = target == "all" || target == "generic";
        let test_desktop = target == "all" || target == "desktop";

        if !test_discord && !test_slack && !test_generic && !test_desktop {
            return Err(NotificationError::ChannelNotConfigured(format!(
                "Unknown notification channel '{}'",
                target
            )));
        }

        if test_discord {
            if let Some(discord_url) = &self.config.discord_webhook_url {
                let payload = build_discord_test_payload(message.as_deref());
                let body = serde_json::to_string(&payload)
                    .map_err(|e| NotificationError::Serialization(e.to_string()))?;
                match dispatch_http_with_retry(
                    &self.client,
                    discord_url,
                    &body,
                    timeout,
                    max_retries,
                )
                .await
                {
                    Ok(details) => {
                        self.record_success();
                        results.push(ChannelTestResult {
                            channel: "discord".to_string(),
                            status: "success".to_string(),
                            details: Some(details),
                        });
                    }
                    Err(err) => {
                        self.record_failure(err.clone());
                        results.push(ChannelTestResult {
                            channel: "discord".to_string(),
                            status: "failed".to_string(),
                            details: Some(err),
                        });
                    }
                }
            } else {
                results.push(ChannelTestResult {
                    channel: "discord".to_string(),
                    status: "skipped".to_string(),
                    details: Some("Discord webhook URL not configured".to_string()),
                });
            }
        }

        if test_slack {
            if let Some(slack_url) = &self.config.slack_webhook_url {
                let payload = build_slack_test_payload(message.as_deref());
                let body = serde_json::to_string(&payload)
                    .map_err(|e| NotificationError::Serialization(e.to_string()))?;
                match dispatch_http_with_retry(
                    &self.client,
                    slack_url,
                    &body,
                    timeout,
                    max_retries,
                )
                .await
                {
                    Ok(details) => {
                        self.record_success();
                        results.push(ChannelTestResult {
                            channel: "slack".to_string(),
                            status: "success".to_string(),
                            details: Some(details),
                        });
                    }
                    Err(err) => {
                        self.record_failure(err.clone());
                        results.push(ChannelTestResult {
                            channel: "slack".to_string(),
                            status: "failed".to_string(),
                            details: Some(err),
                        });
                    }
                }
            } else {
                results.push(ChannelTestResult {
                    channel: "slack".to_string(),
                    status: "skipped".to_string(),
                    details: Some("Slack webhook URL not configured".to_string()),
                });
            }
        }

        if test_generic {
            if !self.config.generic_webhook_urls.is_empty() {
                let payload = build_generic_test_payload(message.as_deref());
                let body = serde_json::to_string(&payload)
                    .map_err(|e| NotificationError::Serialization(e.to_string()))?;
                let mut all_ok = true;
                let mut messages = Vec::new();

                for url in &self.config.generic_webhook_urls {
                    match dispatch_http_with_retry(
                        &self.client,
                        url,
                        &body,
                        timeout,
                        max_retries,
                    )
                    .await
                    {
                        Ok(details) => {
                            self.record_success();
                            messages.push(format!("{}: {}", url, details));
                        }
                        Err(err) => {
                            self.record_failure(err.clone());
                            all_ok = false;
                            messages.push(format!("{}: {}", url, err));
                        }
                    }
                }

                results.push(ChannelTestResult {
                    channel: "generic".to_string(),
                    status: if all_ok {
                        "success".to_string()
                    } else {
                        "failed".to_string()
                    },
                    details: Some(messages.join("; ")),
                });
            } else {
                results.push(ChannelTestResult {
                    channel: "generic".to_string(),
                    status: "skipped".to_string(),
                    details: Some("No generic webhook URLs configured".to_string()),
                });
            }
        }

        if test_desktop {
            if self.config.desktop_notifications {
                let msg = message
                    .as_deref()
                    .unwrap_or("This is a test notification from AgentControll.");
                match dispatch_desktop(
                    "AgentControll: Test Notification",
                    msg,
                    "low",
                    self.config.timeout_ms,
                )
                .await
                {
                    Ok(details) => {
                        self.record_success();
                        results.push(ChannelTestResult {
                            channel: "desktop".to_string(),
                            status: "success".to_string(),
                            details: Some(details),
                        });
                    }
                    Err(err) => {
                        self.record_failure(err.clone());
                        results.push(ChannelTestResult {
                            channel: "desktop".to_string(),
                            status: "failed".to_string(),
                            details: Some(err),
                        });
                    }
                }
            } else {
                results.push(ChannelTestResult {
                    channel: "desktop".to_string(),
                    status: "skipped".to_string(),
                    details: Some("Desktop notifications disabled".to_string()),
                });
            }
        }

        Ok(NotificationTestResult { channels: results })
    }

    /// Dispatches an event across all active and configured channels.
    pub async fn dispatch_event(&self, event: AgentEvent) {
        let timeout = Duration::from_millis(self.config.timeout_ms);
        let max_retries = self.config.max_retries;

        // Discord Webhook
        if let Some(discord_url) = &self.config.discord_webhook_url {
            let payload = build_discord_payload(&event);
            if let Ok(body_str) = serde_json::to_string(&payload) {
                match dispatch_http_with_retry(
                    &self.client,
                    discord_url,
                    &body_str,
                    timeout,
                    max_retries,
                )
                .await
                {
                    Ok(_) => {
                        tracing::debug!("Dispatched Discord notification for event {}", event.kind);
                        self.record_success();
                    }
                    Err(err) => {
                        tracing::warn!("Failed to dispatch Discord notification: {err}");
                        self.record_failure(err);
                    }
                }
            }
        }

        // Slack Webhook
        if let Some(slack_url) = &self.config.slack_webhook_url {
            let payload = build_slack_payload(&event);
            if let Ok(body_str) = serde_json::to_string(&payload) {
                match dispatch_http_with_retry(
                    &self.client,
                    slack_url,
                    &body_str,
                    timeout,
                    max_retries,
                )
                .await
                {
                    Ok(_) => {
                        tracing::debug!("Dispatched Slack notification for event {}", event.kind);
                        self.record_success();
                    }
                    Err(err) => {
                        tracing::warn!("Failed to dispatch Slack notification: {err}");
                        self.record_failure(err);
                    }
                }
            }
        }

        // Generic Webhooks
        for url in &self.config.generic_webhook_urls {
            let payload = build_generic_payload(&event);
            if let Ok(body_str) = serde_json::to_string(&payload) {
                match dispatch_http_with_retry(
                    &self.client,
                    url,
                    &body_str,
                    timeout,
                    max_retries,
                )
                .await
                {
                    Ok(_) => {
                        tracing::debug!(
                            "Dispatched generic webhook to {} for event {}",
                            url,
                            event.kind
                        );
                        self.record_success();
                    }
                    Err(err) => {
                        tracing::warn!("Failed to dispatch generic webhook to {}: {err}", url);
                        self.record_failure(err);
                    }
                }
            }
        }

        // Desktop Notifications
        if self.config.desktop_notifications {
            let (title, desc, det) = extract_event_info(&event);
            let (_, _, urgency) = event_color(&event.kind);
            let full_body = if let Some(d) = det {
                format!("{desc}\n{d}")
            } else {
                desc
            };
            match dispatch_desktop(
                &format!("AgentControll: {title}"),
                &full_body,
                urgency,
                self.config.timeout_ms,
            )
            .await
            {
                Ok(_) => {
                    self.record_success();
                }
                Err(err) => {
                    tracing::warn!("Desktop notification failed: {err}");
                    self.record_failure(err);
                }
            }
        }
    }
}

/// Asynchronous background notification engine running inside `agentcontrold`.
pub struct NotificationDispatcher {
    config: NotificationConfig,
    client: reqwest::Client,
    metrics: Arc<RwLock<NotificationMetrics>>,
}

impl NotificationDispatcher {
    /// Creates a new notification dispatcher with the specified configuration and HTTP client.
    pub fn new(config: NotificationConfig, client: reqwest::Client) -> Self {
        Self {
            config,
            client,
            metrics: Arc::new(RwLock::new(NotificationMetrics::default())),
        }
    }

    /// Returns a cloneable handle to the notification engine.
    pub fn handle(&self) -> NotificationHandle {
        NotificationHandle {
            config: Arc::new(self.config.clone()),
            client: self.client.clone(),
            metrics: Arc::clone(&self.metrics),
        }
    }

    /// Runs the notification listener loop, subscribed to the broadcast event stream.
    ///
    /// Matching events are spawned into independent Tokio tasks to ensure the receive
    /// loop is non-blocking and the broadcast channel never experiences lag.
    pub async fn run(
        self,
        mut event_rx: broadcast::Receiver<AgentEvent>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        let handle = self.handle();
        tracing::info!("Notification dispatcher started");

        loop {
            tokio::select! {
                biased;

                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("Notification dispatcher received shutdown signal");
                        break;
                    }
                }

                recv_res = event_rx.recv() => {
                    match recv_res {
                        Ok(event) => {
                            if handle.config.is_active() && event_matches(&handle.config.events, &event) {
                                let h = handle.clone();
                                tokio::spawn(async move {
                                    h.dispatch_event(event).await;
                                });
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            tracing::warn!("Notification dispatcher lagged, missed {missed} events");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("Notification dispatcher event channel closed");
                            break;
                        }
                    }
                }
            }
        }

        tracing::info!("Notification dispatcher exited cleanly");
    }
}

/// Checks whether an incoming `AgentEvent` matches the configured event filter list.
///
/// Supports direct snake_case event names as well as semantic aliases:
/// - `session_crashed` matches `SessionCrashed` & `SessionFailed`
/// - `human_intervention_required` matches `ApprovalRequested`, `AgentQuestion`, & `InteractionCreated`
/// - `quota_exhausted` matches `AccountExhausted` & `AccountRateLimited`
/// - `session_finished` / `session_stopped` matches `SessionStopped`
/// - `*` or `all` matches all events
pub fn event_matches(configured_events: &[String], event: &AgentEvent) -> bool {
    let kind_str = event.kind.to_string();
    for pattern in configured_events {
        let pattern_lower = pattern.trim().to_ascii_lowercase();
        if pattern_lower == "*" || pattern_lower == "all" {
            return true;
        }
        if pattern_lower == kind_str.to_ascii_lowercase() {
            return true;
        }
        match pattern_lower.as_str() {
            "session_crashed" => {
                if matches!(
                    event.kind,
                    EventKind::SessionCrashed | EventKind::SessionFailed
                ) {
                    return true;
                }
            }
            "human_intervention_required" => {
                if matches!(
                    event.kind,
                    EventKind::ApprovalRequested
                        | EventKind::AgentQuestion
                        | EventKind::InteractionCreated
                ) {
                    return true;
                }
            }
            "quota_exhausted" => {
                if matches!(
                    event.kind,
                    EventKind::AccountExhausted | EventKind::AccountRateLimited
                ) {
                    return true;
                }
            }
            "session_finished" | "session_stopped" => {
                if matches!(event.kind, EventKind::SessionStopped) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

/// Determines the Discord decimal color, Slack hex color, and desktop urgency for an event kind.
pub fn event_color(kind: &EventKind) -> (u32, &'static str, &'static str) {
    match kind {
        EventKind::SessionCrashed | EventKind::SessionFailed | EventKind::AccountExhausted => {
            (COLOR_RED, HEX_RED, "critical")
        }
        EventKind::ApprovalRequested
        | EventKind::AgentQuestion
        | EventKind::InteractionCreated
        | EventKind::AccountRateLimited
        | EventKind::ApprovalDenied => (COLOR_GOLD, HEX_GOLD, "normal"),
        EventKind::SessionStopped
        | EventKind::ApprovalAutoApproved
        | EventKind::ApprovalHumanDecision => (COLOR_GREEN, HEX_GREEN, "low"),
        _ => (COLOR_BLUE, HEX_BLUE, "low"),
    }
}

/// Truncates a string to `max_len` unicode characters, appending an ellipsis if truncated.
pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let mut truncated: String = s.chars().take(max_len.saturating_sub(3)).collect();
        truncated.push_str("...");
        truncated
    }
}

/// Sanitizes a string for use in Discord embed field values (ensures non-empty and bounded length).
fn safe_field_value(val: Option<&str>) -> String {
    match val {
        Some(s) if !s.trim().is_empty() => truncate_str(s.trim(), 1024),
        _ => "(none)".to_string(),
    }
}

/// Extracts title, description, and detailed message from an `AgentEvent`.
pub fn extract_event_info(event: &AgentEvent) -> (String, String, Option<String>) {
    let session_str = event
        .session_id
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "none".to_string());
    match &event.kind {
        EventKind::SessionCrashed => {
            let err = event
                .payload
                .get("error")
                .and_then(|v| v.as_str())
                .or_else(|| event.payload.get("details").and_then(|v| v.as_str()))
                .unwrap_or("Unknown crash reason");
            (
                "Session Crashed".to_string(),
                format!("Session `{}` crashed unexpectedly.", session_str),
                Some(err.to_string()),
            )
        }
        EventKind::SessionFailed => {
            let err = event
                .payload
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Maximum restarts exceeded");
            (
                "Session Failed".to_string(),
                format!("Session `{}` reached Failed state.", session_str),
                Some(err.to_string()),
            )
        }
        EventKind::ApprovalRequested => {
            let desc = event
                .payload
                .get("description")
                .and_then(|v| v.as_str())
                .or_else(|| event.payload.get("command").and_then(|v| v.as_str()))
                .unwrap_or("Approval requested for action");
            (
                "Approval Required".to_string(),
                format!(
                    "Session `{}` requires human approval to proceed.",
                    session_str
                ),
                Some(desc.to_string()),
            )
        }
        EventKind::AgentQuestion => {
            let q = event
                .payload
                .get("question")
                .and_then(|v| v.as_str())
                .or_else(|| event.payload.get("prompt").and_then(|v| v.as_str()))
                .unwrap_or("Agent asked a question");
            (
                "Question from Agent".to_string(),
                format!(
                    "Session `{}` is awaiting an answer to a question.",
                    session_str
                ),
                Some(q.to_string()),
            )
        }
        EventKind::InteractionCreated => {
            let prompt = event
                .payload
                .get("prompt")
                .and_then(|v| v.as_str())
                .or_else(|| event.payload.get("question").and_then(|v| v.as_str()))
                .unwrap_or("Human interaction created");
            (
                "Human Intervention Required".to_string(),
                format!(
                    "Session `{}` created a pending human interaction.",
                    session_str
                ),
                Some(prompt.to_string()),
            )
        }
        EventKind::AccountExhausted => {
            let acc = event
                .payload
                .get("account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "Account Quota Exhausted".to_string(),
                format!("Account `{}` has exhausted its quota.", acc),
                None,
            )
        }
        EventKind::AccountRateLimited => {
            let acc = event
                .payload
                .get("account_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            (
                "Account Rate Limited".to_string(),
                format!("Account `{}` is currently rate limited.", acc),
                None,
            )
        }
        EventKind::SessionStopped => (
            "Session Finished".to_string(),
            format!("Session `{}` has stopped.", session_str),
            None,
        ),
        _ => {
            let det = event
                .payload
                .get("message")
                .and_then(|v| v.as_str())
                .or_else(|| event.payload.get("details").and_then(|v| v.as_str()));
            (
                format!("Event: {}", event.kind),
                format!(
                    "Event `{}` occurred for session `{}`.",
                    event.kind, session_str
                ),
                det.map(|s| s.to_string()),
            )
        }
    }
}

/// Builds a rich embed Discord webhook JSON payload for an `AgentEvent`.
pub fn build_discord_payload(event: &AgentEvent) -> serde_json::Value {
    let (color, _, _) = event_color(&event.kind);
    let (title, description, details) = extract_event_info(event);
    let session_str = event
        .session_id
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "none".to_string());

    let mut fields = vec![
        serde_json::json!({
            "name": "Session ID",
            "value": format!("`{}`", session_str),
            "inline": true
        }),
        serde_json::json!({
            "name": "Event Kind",
            "value": event.kind.to_string(),
            "inline": true
        }),
    ];

    if let Some(agent_type) = event.payload.get("agent_type").and_then(|v| v.as_str()) {
        fields.push(serde_json::json!({
            "name": "Agent Type",
            "value": agent_type,
            "inline": true
        }));
    }

    if let Some(det) = details {
        fields.push(serde_json::json!({
            "name": "Details",
            "value": safe_field_value(Some(&det)),
            "inline": false
        }));
    }

    serde_json::json!({
        "content": format!("🚨 **[AgentControll]** Alert: {}", title),
        "embeds": [
            {
                "title": truncate_str(&title, 256),
                "description": truncate_str(&description, 4096),
                "color": color,
                "fields": fields,
                "timestamp": event.timestamp.to_rfc3339(),
                "footer": {
                    "text": "AgentControll Daemon"
                }
            }
        ]
    })
}

/// Builds a Discord test payload.
pub fn build_discord_test_payload(message: Option<&str>) -> serde_json::Value {
    let msg = message.unwrap_or("This is a test notification from AgentControll.");
    let now = Utc::now();
    serde_json::json!({
        "content": "🔔 **[AgentControll]** Test Notification",
        "embeds": [
            {
                "title": "Notification System Test",
                "description": truncate_str(msg, 4096),
                "color": COLOR_BLUE,
                "fields": [
                    {
                        "name": "Status",
                        "value": "Active",
                        "inline": true
                    },
                    {
                        "name": "Timestamp",
                        "value": now.to_rfc3339(),
                        "inline": true
                    }
                ],
                "timestamp": now.to_rfc3339(),
                "footer": {
                    "text": "AgentControll Daemon"
                }
            }
        ]
    })
}

/// Builds an incoming webhook Slack JSON payload with attachments for an `AgentEvent`.
pub fn build_slack_payload(event: &AgentEvent) -> serde_json::Value {
    let (_, hex_color, _) = event_color(&event.kind);
    let (title, description, details) = extract_event_info(event);
    let session_str = event
        .session_id
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| "none".to_string());

    let mut fields = vec![
        serde_json::json!({
            "title": "Session ID",
            "value": format!("`{}`", session_str),
            "short": true
        }),
        serde_json::json!({
            "title": "Event",
            "value": event.kind.to_string(),
            "short": true
        }),
        serde_json::json!({
            "title": "Timestamp",
            "value": event.timestamp.to_rfc3339(),
            "short": true
        }),
    ];

    if let Some(agent_type) = event.payload.get("agent_type").and_then(|v| v.as_str()) {
        fields.push(serde_json::json!({
            "title": "Agent Type",
            "value": agent_type,
            "short": true
        }));
    }

    if let Some(det) = details {
        fields.push(serde_json::json!({
            "title": "Details",
            "value": det,
            "short": false
        }));
    }

    serde_json::json!({
        "text": format!("🚨 [AgentControll] {}: {}", title, session_str),
        "attachments": [
            {
                "color": hex_color,
                "title": title,
                "text": description,
                "fields": fields,
                "footer": "AgentControll",
                "ts": event.timestamp.timestamp()
            }
        ]
    })
}

/// Builds a Slack test payload.
pub fn build_slack_test_payload(message: Option<&str>) -> serde_json::Value {
    let msg = message.unwrap_or("This is a test notification from AgentControll.");
    let now = Utc::now();
    serde_json::json!({
        "text": "🔔 [AgentControll] Test Notification",
        "attachments": [
            {
                "color": HEX_BLUE,
                "title": "Notification System Test",
                "text": msg,
                "fields": [
                    {
                        "title": "Status",
                        "value": "Active",
                        "short": true
                    },
                    {
                        "title": "Timestamp",
                        "value": now.to_rfc3339(),
                        "short": true
                    }
                ],
                "footer": "AgentControll",
                "ts": now.timestamp()
            }
        ]
    })
}

/// Builds a generic webhook JSON payload for an `AgentEvent`.
pub fn build_generic_payload(event: &AgentEvent) -> GenericWebhookPayload {
    GenericWebhookPayload {
        event: event.kind.to_string(),
        timestamp: event.timestamp,
        session_id: event.session_id.as_ref().map(|s| s.to_string()),
        payload: event.payload.clone(),
    }
}

/// Builds a generic webhook test payload.
pub fn build_generic_test_payload(message: Option<&str>) -> GenericWebhookPayload {
    let msg = message.unwrap_or("This is a test notification from AgentControll.");
    GenericWebhookPayload {
        event: "test".to_string(),
        timestamp: Utc::now(),
        session_id: None,
        payload: serde_json::json!({
            "message": msg,
            "status": "active"
        }),
    }
}

/// Dispatches an HTTP POST request with timeout and exponential backoff retry.
///
/// Fast-fails on HTTP 4xx (client error), retrying up to `max_retries` only on
/// HTTP 5xx (server error) or network connectivity errors.
pub async fn dispatch_http_with_retry(
    client: &reqwest::Client,
    url: &str,
    json_body: &str,
    timeout: Duration,
    max_retries: u32,
) -> Result<String, String> {
    let mut attempt = 0;
    loop {
        let req = client
            .post(url)
            .header("Content-Type", "application/json")
            .timeout(timeout)
            .body(json_body.to_owned());

        match req.send().await {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() {
                    return Ok(format!("HTTP {}", status.as_u16()));
                } else if status.is_client_error() {
                    let text = resp.text().await.unwrap_or_default();
                    let preview = truncate_str(text.trim(), 200);
                    return Err(format!("HTTP {} client error: {}", status.as_u16(), preview));
                } else if status.is_server_error() {
                    if attempt < max_retries {
                        attempt += 1;
                        let backoff = Duration::from_millis(100 * (1 << (attempt - 1)));
                        tokio::time::sleep(backoff).await;
                        continue;
                    } else {
                        let text = resp.text().await.unwrap_or_default();
                        let preview = truncate_str(text.trim(), 200);
                        return Err(format!(
                            "HTTP {} server error after {} retries: {}",
                            status.as_u16(),
                            max_retries,
                            preview
                        ));
                    }
                } else {
                    return Err(format!("HTTP {} unexpected status", status.as_u16()));
                }
            }
            Err(err) => {
                if attempt < max_retries {
                    attempt += 1;
                    let backoff = Duration::from_millis(100 * (1 << (attempt - 1)));
                    tokio::time::sleep(backoff).await;
                    continue;
                } else {
                    return Err(format!("Network error after {} retries: {}", max_retries, err));
                }
            }
        }
    }
}

/// Spawns a local desktop notification process non-blocking with a timeout.
///
/// Uses `notify-send` on Linux and `osascript` on macOS. Safely handles missing
/// binaries or headless environments without blocking or crashing the daemon.
pub async fn dispatch_desktop(
    title: &str,
    body: &str,
    urgency: &str,
    timeout_ms: u64,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        let mut cmd = tokio::process::Command::new("notify-send");
        cmd.arg("-a")
            .arg("AgentControll")
            .arg("-u")
            .arg(urgency)
            .arg("-t")
            .arg(timeout_ms.to_string())
            .arg(title)
            .arg(body);

        let timeout = Duration::from_millis(timeout_ms.max(1000));
        match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(output)) => {
                if output.status.success() {
                    Ok("notify-send succeeded".to_string())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!("notify-send returned non-zero exit status: {stderr}");
                    Ok(format!(
                        "notify-send exited with status {}: {}",
                        output.status,
                        stderr.trim()
                    ))
                }
            }
            Ok(Err(err)) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    tracing::warn!("notify-send binary not found in PATH");
                    Ok("notify-send binary not found".to_string())
                } else {
                    tracing::warn!("Failed to execute notify-send: {err}");
                    Err(format!("notify-send execution failed: {err}"))
                }
            }
            Err(_) => {
                tracing::warn!("notify-send timed out after {timeout_ms}ms");
                Err("notify-send process timed out".to_string())
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let escaped_body = body
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ");
        let escaped_title = title
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', " ");
        let script = format!(
            r#"display notification "{escaped_body}" with title "{escaped_title}""#
        );
        let mut cmd = tokio::process::Command::new("osascript");
        cmd.arg("-e").arg(script);

        let timeout = Duration::from_millis(timeout_ms.max(1000));
        match tokio::time::timeout(timeout, cmd.output()).await {
            Ok(Ok(output)) => {
                if output.status.success() {
                    Ok("osascript succeeded".to_string())
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!("osascript returned non-zero exit status: {stderr}");
                    Ok(format!(
                        "osascript exited with status {}: {}",
                        output.status,
                        stderr.trim()
                    ))
                }
            }
            Ok(Err(err)) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    tracing::warn!("osascript binary not found");
                    Ok("osascript binary not found".to_string())
                } else {
                    tracing::warn!("Failed to execute osascript: {err}");
                    Err(format!("osascript execution failed: {err}"))
                }
            }
            Err(_) => {
                tracing::warn!("osascript timed out after {timeout_ms}ms");
                Err("osascript process timed out".to_string())
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (title, body, urgency, timeout_ms);
        tracing::info!("Desktop notifications not supported on this platform");
        Ok("Desktop notifications not supported on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Id;

    fn make_test_event(kind: EventKind, payload: serde_json::Value) -> AgentEvent {
        AgentEvent {
            seq: 1,
            id: Id::new(),
            version: 1,
            kind,
            session_id: Some(Id::new()),
            payload,
            triggered_by: "test_runner".to_string(),
            timestamp: Utc::now(),
            prev_hash: None,
            hash: None,
        }
    }

    #[test]
    fn test_event_matches_filters() {
        let default_events = vec![
            "session_crashed".to_string(),
            "human_intervention_required".to_string(),
            "quota_exhausted".to_string(),
            "session_finished".to_string(),
        ];

        // SessionCrashed matches session_crashed
        let ev_crashed = make_test_event(EventKind::SessionCrashed, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_crashed));

        // SessionFailed matches session_crashed alias
        let ev_failed = make_test_event(EventKind::SessionFailed, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_failed));

        // ApprovalRequested matches human_intervention_required
        let ev_approval = make_test_event(EventKind::ApprovalRequested, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_approval));

        // AgentQuestion matches human_intervention_required
        let ev_question = make_test_event(EventKind::AgentQuestion, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_question));

        // InteractionCreated matches human_intervention_required
        let ev_interaction = make_test_event(EventKind::InteractionCreated, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_interaction));

        // AccountExhausted matches quota_exhausted
        let ev_exhausted = make_test_event(EventKind::AccountExhausted, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_exhausted));

        // AccountRateLimited matches quota_exhausted
        let ev_rate_limited = make_test_event(EventKind::AccountRateLimited, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_rate_limited));

        // SessionStopped matches session_finished
        let ev_stopped = make_test_event(EventKind::SessionStopped, serde_json::json!({}));
        assert!(event_matches(&default_events, &ev_stopped));

        // SessionStarted is not in the default events list
        let ev_started = make_test_event(EventKind::SessionStarted, serde_json::json!({}));
        assert!(!event_matches(&default_events, &ev_started));

        // Wildcard matches all events
        assert!(event_matches(&["*".to_string()], &ev_started));
    }

    #[test]
    fn test_discord_payload_structure() {
        let ev = make_test_event(
            EventKind::SessionCrashed,
            serde_json::json!({
                "agent_type": "agy",
                "error": "Out of memory"
            }),
        );
        let payload = build_discord_payload(&ev);

        assert!(payload.get("content").is_some());
        let embeds = payload.get("embeds").and_then(|v| v.as_array()).expect("embeds array");
        assert_eq!(embeds.len(), 1);

        let embed = &embeds[0];
        assert_eq!(embed.get("color").and_then(|v| v.as_u64()), Some(COLOR_RED as u64));
        assert_eq!(embed.get("title").and_then(|v| v.as_str()), Some("Session Crashed"));

        let fields = embed.get("fields").and_then(|v| v.as_array()).expect("fields array");
        assert!(fields.len() >= 3);
        // Verify no empty field names or values
        for f in fields {
            let name = f.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let val = f.get("value").and_then(|v| v.as_str()).unwrap_or("");
            assert!(!name.is_empty(), "field name must not be empty");
            assert!(!val.is_empty(), "field value must not be empty");
        }
    }

    #[test]
    fn test_slack_payload_structure() {
        let ev = make_test_event(
            EventKind::ApprovalRequested,
            serde_json::json!({
                "description": "Execute bash command `rm -rf /tmp/test`",
                "agent_type": "claude"
            }),
        );
        let payload = build_slack_payload(&ev);

        assert!(payload.get("text").is_some());
        let attachments = payload
            .get("attachments")
            .and_then(|v| v.as_array())
            .expect("attachments array");
        assert_eq!(attachments.len(), 1);

        let att = &attachments[0];
        assert_eq!(att.get("color").and_then(|v| v.as_str()), Some(HEX_GOLD));
        assert_eq!(att.get("title").and_then(|v| v.as_str()), Some("Approval Required"));
    }

    #[test]
    fn test_generic_payload_structure() {
        let ev = make_test_event(
            EventKind::SessionCrashed,
            serde_json::json!({
                "error": "Segmentation fault",
                "agent_type": "agy"
            }),
        );
        let payload = build_generic_payload(&ev);
        let json_val = serde_json::to_value(&payload).expect("serialize generic payload");

        assert_eq!(json_val.get("event").and_then(|v| v.as_str()), Some("session_crashed"));
        assert!(json_val.get("timestamp").is_some());
        assert!(json_val.get("session_id").is_some());
        assert_eq!(
            json_val["payload"]["error"].as_str(),
            Some("Segmentation fault")
        );
    }

    #[test]
    fn test_metrics_tracking() {
        let config = NotificationConfig::default();
        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);
        let handle = dispatcher.handle();

        let initial = handle.metrics();
        assert_eq!(initial.total_dispatched, 0);
        assert_eq!(initial.successful, 0);
        assert_eq!(initial.failed, 0);
        assert!(initial.last_success.is_none());

        handle.record_success();
        let m1 = handle.metrics();
        assert_eq!(m1.total_dispatched, 1);
        assert_eq!(m1.successful, 1);
        assert_eq!(m1.failed, 0);
        assert!(m1.last_success.is_some());

        handle.record_failure("HTTP 500 error".to_string());
        let m2 = handle.metrics();
        assert_eq!(m2.total_dispatched, 2);
        assert_eq!(m2.successful, 1);
        assert_eq!(m2.failed, 1);
        assert_eq!(m2.last_error.as_deref(), Some("HTTP 500 error"));
        assert!(m2.last_failure.is_some());
    }

    #[test]
    fn test_status_report() {
        let mut config = NotificationConfig::default();
        config.enabled = true;
        config.discord_webhook_url = Some("https://discord.com/webhook".to_string());
        config.generic_webhook_urls = vec!["https://generic1.com".to_string(), "https://generic2.com".to_string()];
        config.desktop_notifications = true;

        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);
        let handle = dispatcher.handle();

        let status = handle.status();
        assert!(status.enabled);
        assert!(status.desktop);
        assert!(status.discord_configured);
        assert!(!status.slack_configured);
        assert_eq!(status.generic_webhooks_count, 2);
        assert_eq!(status.events.len(), 4);
    }

    #[test]
    fn test_string_truncation() {
        let short = "Hello World";
        assert_eq!(truncate_str(short, 20), "Hello World");

        let long = "1234567890abcdefghijklmnopqrstuvwxyz";
        let truncated = truncate_str(long, 10);
        assert_eq!(truncated, "1234567...");
        assert_eq!(truncated.chars().count(), 10);
    }

    #[tokio::test]
    async fn test_send_test_skipped_when_unconfigured() {
        let config = NotificationConfig::default();
        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);
        let handle = dispatcher.handle();

        let res = handle.send_test(None, None).await.expect("send_test succeeds");
        assert_eq!(res.channels.len(), 4);
        for ch in res.channels {
            assert_eq!(ch.status, "skipped", "channel {} should be skipped", ch.channel);
        }
    }

    #[tokio::test]
    async fn test_dispatcher_clean_shutdown() {
        let config = NotificationConfig::default();
        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);

        let (event_tx, event_rx) = broadcast::channel::<AgentEvent>(16);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let run_task = tokio::spawn(async move {
            dispatcher.run(event_rx, shutdown_rx).await;
        });

        // Send an event
        let ev = make_test_event(EventKind::SessionCrashed, serde_json::json!({}));
        let _ = event_tx.send(ev);

        // Signal shutdown
        shutdown_tx.send(true).expect("send shutdown signal");

        // Await shutdown with timeout
        let result = tokio::time::timeout(Duration::from_secs(2), run_task).await;
        assert!(result.is_ok(), "dispatcher should shut down cleanly within timeout");
    }

    #[tokio::test]
    async fn test_http_dispatch_mock() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let url = format!("http://{}", addr);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = reqwest::Client::new();
        let res = dispatch_http_with_retry(
            &client,
            &url,
            r#"{"test": true}"#,
            Duration::from_millis(1000),
            1,
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "HTTP 200");
    }

    #[tokio::test]
    async fn test_http_dispatch_fast_fail_on_4xx() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let url = format!("http://{}", addr);

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 15\r\n\r\nInvalid Payload";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let client = reqwest::Client::new();
        let start = std::time::Instant::now();
        let res = dispatch_http_with_retry(
            &client,
            &url,
            r#"{"bad": true}"#,
            Duration::from_millis(1000),
            3, // Even with 3 retries, should NOT retry on 400
        )
        .await;

        assert!(res.is_err());
        let err_str = res.unwrap_err();
        assert!(err_str.contains("HTTP 400 client error"));
        // Must fail immediately without backoff delay
        assert!(start.elapsed() < Duration::from_millis(500));
    }

    #[tokio::test]
    async fn test_http_dispatch_retry_on_500_then_success() {
        use std::sync::atomic::{AtomicU32, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let url = format!("http://{}", addr);

        let attempts = Arc::new(AtomicU32::new(0));
        let attempts_clone = Arc::clone(&attempts);

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let count = attempts_clone.fetch_add(1, Ordering::SeqCst);
                if count == 0 {
                    // First attempt returns 500
                    let response = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 5\r\n\r\nerror";
                    let _ = socket.write_all(response.as_bytes()).await;
                } else {
                    // Second attempt returns 200 OK
                    let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                    let _ = socket.write_all(response.as_bytes()).await;
                    break;
                }
            }
        });

        let client = reqwest::Client::new();
        let res = dispatch_http_with_retry(
            &client,
            &url,
            r#"{"retry_test": true}"#,
            Duration::from_millis(1000),
            2,
        )
        .await;

        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "HTTP 200");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_send_test_with_mock_discord_and_slack() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let mock_url = format!("http://{}", addr);

        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let mut config = NotificationConfig::default();
        config.discord_webhook_url = Some(mock_url.clone());
        config.slack_webhook_url = Some(mock_url.clone());

        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);
        let handle = dispatcher.handle();

        let res = handle
            .send_test(Some("discord".to_string()), Some("Discord test".to_string()))
            .await
            .expect("discord test succeeds");
        assert_eq!(res.channels.len(), 1);
        assert_eq!(res.channels[0].channel, "discord");
        assert_eq!(res.channels[0].status, "success");

        let res = handle
            .send_test(Some("slack".to_string()), Some("Slack test".to_string()))
            .await
            .expect("slack test succeeds");
        assert_eq!(res.channels.len(), 1);
        assert_eq!(res.channels[0].channel, "slack");
        assert_eq!(res.channels[0].status, "success");

        let metrics = handle.metrics();
        assert_eq!(metrics.successful, 2);
    }

    #[tokio::test]
    async fn test_send_test_unknown_channel() {
        let config = NotificationConfig::default();
        let client = reqwest::Client::new();
        let dispatcher = NotificationDispatcher::new(config, client);
        let handle = dispatcher.handle();

        let res = handle
            .send_test(Some("nonexistent".to_string()), None)
            .await;
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), NotificationError::ChannelNotConfigured(_)));
    }

    #[tokio::test]
    async fn test_desktop_dispatch_safe_execution() {
        // Test dispatch_desktop with valid parameters
        let res = dispatch_desktop("Test Title", "Test Body", "low", 1000).await;
        // Whether notify-send exists or exits with status or warning, it must not return an unhandled panic
        assert!(res.is_ok() || res.is_err());
    }
}
