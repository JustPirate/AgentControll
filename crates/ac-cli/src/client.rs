//! Client for interacting with the Agent Control daemon over Unix domain socket.

use anyhow::{Context, Result};
use serde_json::json;
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::mpsc,
};
use tracing::debug;

use ac_core::types::{
    Account, AgentEvent, AgentSession, ApiRequest, ApiResponse, AuditIntegrityReport, Id, Project,
    SessionTemplate, SubscriptionFilter,
};

#[derive(Debug, Clone)]
pub struct DaemonClient {
    pub socket_path: PathBuf,
}

impl DaemonClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub fn default_client() -> Self {
        let path = std::env::var("AC_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|_| ac_core::config::Config::default().socket_path);
        Self::new(path)
    }

    /// Check if the daemon is currently reachable.
    pub async fn is_running(&self) -> bool {
        UnixStream::connect(&self.socket_path).await.is_ok()
    }

    /// Ensure the daemon is running, attempting to start it in the background if not.
    pub async fn ensure_daemon_running(&self) -> Result<()> {
        if self.is_running().await {
            return Ok(());
        }

        // Attempt to find agentcontrold
        let mut candidates = Vec::new();
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                candidates.push(parent.join("agentcontrold"));
            }
        }
        candidates.push(PathBuf::from("agentcontrold"));

        let mut spawned = false;
        for candidate in candidates {
            if candidate.is_file() || candidate.as_os_str() == "agentcontrold" {
                debug!("Attempting to spawn daemon: {}", candidate.display());
                let mut cmd = std::process::Command::new(&candidate);
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .stdin(std::process::Stdio::null());
                #[cfg(unix)]
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(|| {
                        libc::setsid();
                        libc::signal(libc::SIGHUP, libc::SIG_IGN);
                        Ok(())
                    });
                }
                if let Ok(child) = cmd.spawn() {
                    std::mem::forget(child); // Let it run as an independent daemon process
                    spawned = true;
                    break;
                }
            }
        }

        if spawned {
            // Wait up to 3 seconds for the socket to become available
            for _ in 0..30 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if self.is_running().await {
                    return Ok(());
                }
            }
        }

        if !self.is_running().await {
            anyhow::bail!(
                "Cannot connect to Agent Control daemon at {}.\nPlease start the daemon using: agentcontrold",
                self.socket_path.display()
            );
        }

        Ok(())
    }

    /// Send a request and wait for a response.
    pub async fn send_command(&self, cmd: &str, params: serde_json::Value) -> Result<ApiResponse> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connecting to daemon at {}", self.socket_path.display()))?;

        let (read_half, mut write_half) = stream.into_split();
        let req = ApiRequest {
            v: 1,
            id: ulid::Ulid::new().to_string(),
            cmd: cmd.to_owned(),
            params,
        };

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        write_half.write_all(line.as_bytes()).await?;

        let reader = BufReader::new(read_half);
        let mut lines = reader.lines();
        let response_line = lines
            .next_line()
            .await?
            .context("Daemon closed connection without responding")?;

        let resp: ApiResponse =
            serde_json::from_str(&response_line).context("Failed to parse daemon response")?;
        Ok(resp)
    }

    /// List all registered accounts.
    pub async fn list_accounts(&self) -> Result<Vec<Account>> {
        let resp = self.send_command("account.list", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to list accounts: {msg}");
        }
        let result = resp.result.unwrap_or(json!({}));
        let accounts: Vec<Account> =
            serde_json::from_value(result["accounts"].clone()).unwrap_or_default();
        Ok(accounts)
    }

    /// Register a new account.
    pub async fn register_account(
        &self,
        label: &str,
        provider: &str,
        agent_types: &[&str],
        credential_ref: &str,
        concurrency_cap: u8,
        tags: &[&str],
    ) -> Result<Id> {
        let resp = self
            .send_command(
                "account.register",
                json!({
                    "label": label,
                    "provider": provider,
                    "agent_types": agent_types,
                    "credential_ref": credential_ref,
                    "concurrency_cap": concurrency_cap,
                    "tags": tags,
                }),
            )
            .await?;

        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to register account: {msg}");
        }

        let aid = resp
            .result
            .and_then(|r| r["account_id"].as_str().map(Id::from))
            .context("Missing account_id in response")?;
        Ok(aid)
    }

    /// Remove an account by exact ID. Returns cleanup errors (empty on full success).
    pub async fn remove_account(&self, account_id: &Id) -> Result<Vec<String>> {
        let resp = self
            .send_command("account.remove", json!({ "account_id": account_id }))
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("{msg}");
        }
        Ok(resp
            .result
            .and_then(|r| serde_json::from_value(r["cleanup_errors"].clone()).ok())
            .unwrap_or_default())
    }

    /// List all sessions.
    pub async fn list_sessions(&self) -> Result<Vec<AgentSession>> {
        let resp = self.send_command("session.list", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to list sessions: {msg}");
        }
        let result = resp.result.unwrap_or(json!({}));
        let sessions: Vec<AgentSession> =
            serde_json::from_value(result["sessions"].clone()).unwrap_or_default();
        Ok(sessions)
    }

    /// Get session details by ID.
    pub async fn get_session(&self, session_id: &Id) -> Result<Option<AgentSession>> {
        let resp = self
            .send_command("session.get", json!({ "session_id": session_id }))
            .await?;
        if !resp.ok {
            if let Some(ref err) = resp.error {
                if err.code == "NotFound" {
                    return Ok(None);
                }
            }
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to get session: {msg}");
        }
        let result = resp.result.context("Missing result in session.get")?;
        let session: AgentSession = serde_json::from_value(result)?;
        Ok(Some(session))
    }

    /// Create and immediately start a session.
    pub async fn create_and_start_session(
        &self,
        task_description: &str,
        agent_type: &str,
        project_id: Option<Id>,
        account_id: Option<Id>,
    ) -> Result<Id> {
        let resp = self
            .send_command(
                "session.create_and_start",
                json!({
                    "task_description": task_description,
                    "agent_type": agent_type,
                    "project_id": project_id,
                    "account_id": account_id,
                }),
            )
            .await?;

        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("{msg}");
        }

        let sid = resp
            .result
            .and_then(|r| r["session_id"].as_str().map(Id::from))
            .context("Missing session_id in create_and_start response")?;
        Ok(sid)
    }

    /// Pause a running session.
    pub async fn pause_session(&self, session_id: &Id) -> Result<()> {
        let resp = self
            .send_command("session.pause", json!({ "session_id": session_id }))
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to pause session: {msg}");
        }
        Ok(())
    }

    /// Resume a paused session (or restart a stopped/crashed session).
    pub async fn resume_session(&self, session_id: &Id) -> Result<()> {
        let resp = self
            .send_command("session.resume", json!({ "session_id": session_id }))
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to resume session: {msg}");
        }
        Ok(())
    }

    /// Discover conversations across host storage and account profiles.
    pub async fn list_conversations(
        &self,
    ) -> Result<Vec<ac_core::agy_discovery::DiscoveredConversation>> {
        let resp = self.send_command("conversation.list", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to list conversations: {msg}");
        }
        let list = resp
            .result
            .and_then(|r| r.get("conversations").cloned())
            .unwrap_or_else(|| json!([]));
        let convs = serde_json::from_value(list)?;
        Ok(convs)
    }

    /// Stop a session.
    pub async fn stop_session(&self, session_id: &Id, reason: Option<&str>) -> Result<()> {
        let resp = self
            .send_command(
                "session.stop",
                json!({ "session_id": session_id, "reason": reason }),
            )
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to stop session: {msg}");
        }
        Ok(())
    }

    /// Remove/delete a session.
    pub async fn remove_session(&self, session_id: &Id) -> Result<()> {
        let resp = self
            .send_command("session.remove", json!({ "session_id": session_id }))
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to remove session: {msg}");
        }
        Ok(())
    }

    /// Steer a running session by injecting a human instruction.
    pub async fn steer_session(&self, session_id: &Id, message: &str) -> Result<()> {
        let resp = self
            .send_command(
                "session.steer",
                json!({ "session_id": session_id, "message": message }),
            )
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to steer session: {msg}");
        }
        Ok(())
    }

    /// Switch account for a session (using controlled hand-off).
    pub async fn switch_account(&self, session_id: &Id, target_account_id: &Id) -> Result<Id> {
        let resp = self
            .send_command(
                "session.switch_account",
                json!({
                    "session_id": session_id,
                    "target_account_id": target_account_id,
                }),
            )
            .await?;

        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("{msg}");
        }

        let sid = resp
            .result
            .and_then(|r| {
                r["active_session_id"]
                    .as_str()
                    .or_else(|| r["successor_session_id"].as_str())
                    .or_else(|| r["session_id"].as_str())
                    .map(Id::from)
            })
            .context("Missing successor session ID in switch_account response")?;
        Ok(sid)
    }

    /// List all registered projects.
    pub async fn list_projects(&self) -> Result<Vec<Project>> {
        let resp = self.send_command("project.list", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to list projects: {msg}");
        }
        let result = resp.result.unwrap_or(json!({}));
        let projects: Vec<Project> =
            serde_json::from_value(result["projects"].clone()).unwrap_or_default();
        Ok(projects)
    }

    /// Register a new project.
    pub async fn register_project(
        &self,
        name: &str,
        repo_path: &str,
        default_agent_type: Option<&str>,
        default_account_tags: &[&str],
        workspace_policy: &str,
    ) -> Result<Id> {
        let resp = self
            .send_command(
                "project.register",
                json!({
                    "name": name,
                    "repo_path": repo_path,
                    "default_agent_type": default_agent_type,
                    "default_account_tags": default_account_tags,
                    "workspace_policy": workspace_policy,
                }),
            )
            .await?;

        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to register project: {msg}");
        }

        let pid = resp
            .result
            .and_then(|r| r["project_id"].as_str().map(Id::from))
            .context("Missing project_id in response")?;
        Ok(pid)
    }

    /// Query historical events for a session.
    pub async fn query_events(
        &self,
        session_id: &Id,
        limit: Option<u64>,
    ) -> Result<Vec<AgentEvent>> {
        let resp = self
            .send_command(
                "events.query",
                json!({ "session_id": session_id, "limit": limit }),
            )
            .await?;

        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to query events: {msg}");
        }

        let result = resp.result.unwrap_or(json!({}));
        let events: Vec<AgentEvent> =
            serde_json::from_value(result["events"].clone()).unwrap_or_default();
        Ok(events)
    }

    /// Subscribe to live events, optionally filtered by session ID.
    pub async fn subscribe_events(
        &self,
        session_id: Option<Id>,
    ) -> Result<mpsc::Receiver<AgentEvent>> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| format!("connecting to daemon at {}", self.socket_path.display()))?;

        let (read_half, mut write_half) = stream.into_split();
        let filter = SubscriptionFilter {
            session_id,
            ..Default::default()
        };

        let req = ApiRequest {
            v: 1,
            id: "sub-live".to_owned(),
            cmd: "events.subscribe".to_owned(),
            params: json!({ "filter": filter }),
        };

        let mut line = serde_json::to_string(&req)?;
        line.push('\n');
        write_half.write_all(line.as_bytes()).await?;

        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            let reader = BufReader::new(read_half);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                if line.trim().is_empty() {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<AgentEvent>(&line) {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }

    /// List all session templates.
    pub async fn list_templates(&self) -> Result<Vec<SessionTemplate>> {
        let resp = self.send_command("template.list", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to list templates: {msg}");
        }
        let result = resp.result.unwrap_or(json!({}));
        let templates: Vec<SessionTemplate> =
            serde_json::from_value(result["templates"].clone()).unwrap_or_default();
        Ok(templates)
    }

    /// Retrieve a session template by slug name or ULID ID.
    pub async fn get_template(&self, template: &str) -> Result<Option<SessionTemplate>> {
        let resp = self
            .send_command("template.get", json!({ "template": template }))
            .await?;
        if !resp.ok {
            if let Some(ref err) = resp.error {
                if err.code == "NotFound" {
                    return Ok(None);
                }
            }
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to get template: {msg}");
        }
        let result = resp.result.context("Missing result in template.get")?;
        let tmpl: SessionTemplate = serde_json::from_value(result["template"].clone())
            .context("Failed to deserialize SessionTemplate")?;
        Ok(Some(tmpl))
    }

    /// Create a new session template.
    pub async fn create_template(&self, template: &SessionTemplate) -> Result<Id> {
        let mut params = json!({
            "name": template.name,
            "agent_type": template.agent_type,
        });
        if let Some(ref d) = template.description {
            params["description"] = json!(d);
        }
        if let Some(ref p) = template.default_task_prompt {
            params["default_task_prompt"] = json!(p);
        }
        if let Some(ref t) = template.account_tag {
            params["account_tag"] = json!(t);
        }
        if let Some(ref pm) = template.permission_mode {
            params["permission_mode"] = json!(pm);
        }
        if let Some(ref m) = template.model {
            params["model"] = json!(m);
        }
        if let Some(ref l) = template.launch_options {
            params["launch"] = serde_json::to_value(l)?;
        }

        let resp = self.send_command("template.create", params).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to create template: {msg}");
        }

        let tid = resp
            .result
            .and_then(|r| r["template_id"].as_str().map(Id::from))
            .context("Missing template_id in template.create response")?;
        Ok(tid)
    }

    /// Delete a session template by slug name or ULID ID.
    pub async fn delete_template(&self, template: &str) -> Result<()> {
        let resp = self
            .send_command("template.delete", json!({ "template": template }))
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to delete template: {msg}");
        }
        Ok(())
    }

    /// Create and start a session configured by a session template.
    pub async fn create_session_from_template(
        &self,
        template: &str,
        task_override: Option<&str>,
    ) -> Result<Id> {
        let mut params = json!({
            "template": template,
            "start": true,
        });
        if let Some(t) = task_override {
            params["task_description"] = json!(t);
        }
        let resp = self
            .send_command("session.create_from_template", params)
            .await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to launch from template: {msg}");
        }

        let sid = resp
            .result
            .and_then(|r| r["session_id"].as_str().map(Id::from))
            .context("Missing session_id in create_session_from_template response")?;
        Ok(sid)
    }

    /// Retrieve metrics from the daemon (Feature F12).
    pub async fn get_metrics(&self) -> Result<serde_json::Value> {
        let resp = self.send_command("metrics.get", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Failed to get metrics: {msg}");
        }
        resp.result.context("Missing result in metrics.get response")
    }

    /// Retrieve notification configuration and delivery metrics (Feature F8).
    pub async fn notification_status(&self) -> Result<ApiResponse> {
        self.send_command("notification.status", json!({})).await
    }

    /// Trigger test notification across configured channels (Feature F8).
    pub async fn notification_test(
        &self,
        channel: Option<&str>,
        message: Option<&str>,
    ) -> Result<ApiResponse> {
        self.send_command(
            "notification.test",
            json!({
                "channel": channel,
                "message": message,
            }),
        )
        .await
    }

    /// Cryptographically verify audit log hash chain via the daemon (F7 / ADR-010).
    pub async fn verify_audit(&self) -> Result<AuditIntegrityReport> {
        let resp = self.send_command("audit.verify", json!({})).await?;
        if !resp.ok {
            let msg = resp
                .error
                .map(|e| e.message)
                .unwrap_or_else(|| "Unknown error".into());
            anyhow::bail!("Daemon audit verification failed: {msg}");
        }
        serde_json::from_value(resp.result.unwrap_or(serde_json::Value::Null))
            .context("Failed to deserialize AuditIntegrityReport from daemon")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn test_daemon_client_notification_status() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let client = DaemonClient::new(sock_path.clone());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let reader = BufReader::new(read_half);
            let mut lines = reader.lines();
            let line = lines.next_line().await.unwrap().unwrap();
            let req: ApiRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(req.cmd, "notification.status");
            assert_eq!(req.params, json!({}));

            let resp = ApiResponse::ok(
                &req.id,
                json!({
                    "status": {
                        "enabled": true,
                        "desktop": false,
                        "discord_configured": true,
                        "slack_configured": false,
                        "generic_webhooks_count": 1,
                        "events": ["session_crashed"],
                        "metrics": {
                            "total_dispatched": 5,
                            "successful": 5,
                            "failed": 0,
                            "last_success": null,
                            "last_failure": null,
                            "last_error": null
                        }
                    }
                }),
            );
            let mut resp_str = serde_json::to_string(&resp).unwrap();
            resp_str.push('\n');
            write_half.write_all(resp_str.as_bytes()).await.unwrap();
        });

        let resp = client.notification_status().await.unwrap();
        assert!(resp.ok);
        let res = resp.result.unwrap();
        assert_eq!(res["status"]["enabled"], true);
        assert_eq!(res["status"]["generic_webhooks_count"], 1);
    }

    #[tokio::test]
    async fn test_daemon_client_notification_test() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("test_test.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();

        let client = DaemonClient::new(sock_path.clone());

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let reader = BufReader::new(read_half);
            let mut lines = reader.lines();
            let line = lines.next_line().await.unwrap().unwrap();
            let req: ApiRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(req.cmd, "notification.test");
            assert_eq!(req.params["channel"], "discord");
            assert_eq!(req.params["message"], "test dispatch");

            let resp = ApiResponse::ok(
                &req.id,
                json!({
                    "test_results": {
                        "channels": [
                            {
                                "channel": "discord",
                                "status": "success",
                                "details": "HTTP 204 No Content"
                            }
                        ]
                    }
                }),
            );
            let mut resp_str = serde_json::to_string(&resp).unwrap();
            resp_str.push('\n');
            write_half.write_all(resp_str.as_bytes()).await.unwrap();
        });

        let resp = client
            .notification_test(Some("discord"), Some("test dispatch"))
            .await
            .unwrap();
        assert!(resp.ok);
        let res = resp.result.unwrap();
        let channels = res["test_results"]["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 1);
        assert_eq!(channels[0]["channel"], "discord");
        assert_eq!(channels[0]["status"], "success");
    }
}
