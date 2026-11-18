//! `ac` — Agent Control CLI
//!
//! Communicates with the daemon via the Unix domain socket.
//! Each command sends a JSON request and prints the JSON response.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::io::IsTerminal;
use std::path::PathBuf;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use ac_core::types::{ApiRequest, ApiResponse};

// ── CLI definition ────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "ac",
    version,
    about = "AgentControll CLI",
    long_about = "Control AgentControll daemon sessions and events from the command line."
)]
struct Cli {
    /// Path to the daemon Unix socket.
    #[arg(
        long,
        env = "AC_SOCKET",
        default_value_os_t = ac_core::config::Config::default().socket_path
    )]
    socket: PathBuf,

    /// Output raw JSON responses (default: pretty-printed).
    #[arg(long)]
    json: bool,

    /// Output plain tab-delimited text without headers or dividers (ideal for unix pipes and scripts).
    #[arg(long, short = 'p')]
    plain: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Session management commands.
    #[command(subcommand)]
    Session(SessionCmd),
    /// Reusable session templates & presets.
    #[command(subcommand)]
    Template(TemplateCmd),
    /// Conversation inspection and discovery commands.
    #[command(subcommand)]
    Conversation(ConversationCmd),
    /// Account management commands.
    #[command(subcommand)]
    Account(AccountCmd),
    /// Project management commands.
    #[command(subcommand)]
    Project(ProjectCmd),
    /// Interaction management commands (Phase 3).
    #[command(subcommand)]
    Interaction(InteractionCmd),
    /// Policy management commands (Phase 3).
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Audit log commands (Phase 3).
    #[command(subcommand)]
    Audit(AuditCmd),
    /// Event log commands.
    #[command(subcommand)]
    Events(EventsCmd),
    /// View native metrics and OpenTelemetry data from the daemon.
    Metrics {
        /// Output metrics in structured JSON format instead of Prometheus text format.
        #[arg(long)]
        json: bool,
    },
    /// External notification and webhook management (Feature F8).
    #[command(subcommand, alias = "notify")]
    Notification(NotificationCmd),
    /// Daemon status.
    Status,
    /// Log in to an account (e.g. Antigravity / Google).
    Login {
        /// Optional friendly label for the account.
        #[arg(short, long)]
        name: Option<String>,
        /// Don't open a browser: print the login URL and paste the redirect URL back.
        #[arg(long)]
        cli: bool,
    },
    /// Launch the interactive Ratatui TUI dashboard.
    Tui,
    /// Launch the interactive Ratatui TUI dashboard (alias for tui).
    Dashboard,
    /// Diagnose AgentControll installation, configuration, Antigravity integration, accounts, profiles, and sessions.
    Doctor {
        /// Perform additional safe deep diagnostics.
        #[arg(long)]
        deep: bool,
        /// Return machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// External notification and webhook management subcommands (Feature F8).
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
enum NotificationCmd {
    /// Dispatch a test notification to configured webhooks and desktop alerts.
    Test {
        /// Specific channel to test (discord, slack, generic, desktop, or all).
        #[arg(short, long)]
        channel: Option<String>,
        /// Custom message body for the test notification.
        #[arg(short, long)]
        message: Option<String>,
    },
    /// Inspect notification configuration and delivery metrics.
    Status,
}

/// Conversation inspection and discovery subcommands.
#[derive(Subcommand)]
enum ConversationCmd {
    /// List discovered conversations from host storage and account profiles.
    List,
}

/// Template management subcommands.
#[derive(Subcommand)]
enum TemplateCmd {
    /// List all session templates.
    List,
    /// Create a new session template.
    Create {
        /// Unique template slug/name (alphanumeric and dashes).
        #[arg(long)]
        name: String,
        /// Optional human-readable description of this template.
        #[arg(long)]
        description: Option<String>,
        /// Target agent type (default: agy).
        #[arg(long, default_value = "agy")]
        agent_type: String,
        /// Default task description / prompt.
        #[arg(long, alias = "default-task-prompt", alias = "task")]
        prompt: Option<String>,
        /// Model ID override (e.g. gemini-3.8-flash-medium).
        #[arg(long)]
        model: Option<String>,
        /// Permission mode override (e.g. normal, dangerously-skip-permissions).
        #[arg(long)]
        permission_mode: Option<String>,
        /// Account tag or selector for automatic account assignment.
        #[arg(long, alias = "tag")]
        account_tag: Option<String>,
        /// Antigravity execution mode (e.g. plan, accept-edits).
        #[arg(long)]
        execution_mode: Option<String>,
        /// Run in isolated sandbox container.
        #[arg(long)]
        sandbox: bool,
        /// Initial working directory for the agent session.
        #[arg(long, alias = "cwd")]
        working_dir: Option<String>,
    },
    /// Get details for a specific template.
    Get {
        /// Template name or ID.
        template: String,
    },
    /// Delete a session template.
    #[command(alias = "remove")]
    Delete {
        /// Template name or ID.
        template: String,
    },
    /// Create and immediately start a session configured by a template.
    Run {
        /// Template name or ID.
        template: String,
        /// Task description override for the agent.
        #[arg(short, long)]
        task: Option<String>,
        /// Optional project ID.
        #[arg(long)]
        project_id: Option<String>,
        /// Optional explicit account ID.
        #[arg(long)]
        account_id: Option<String>,
        /// Optional conversation ID to resume.
        #[arg(short = 'c', long = "conversation")]
        conversation: Option<String>,
    },
}

#[derive(Subcommand)]
enum SessionCmd {
    /// Create a new session (without starting it).
    Create {
        /// Task description for the agent.
        #[arg(short, long)]
        task: String,
        /// Agent type (default: agy).
        #[arg(short, long, default_value = "agy")]
        agent_type: String,
        /// Optional project ID.
        #[arg(long)]
        project_id: Option<String>,
        /// Optional explicit account ID.
        #[arg(long)]
        account_id: Option<String>,
        /// Optional conversation ID to resume.
        #[arg(short = 'c', long = "conversation")]
        conversation: Option<String>,
        /// Force enable kernel filesystem sandbox (Landlock).
        #[arg(long, conflicts_with = "no_sandbox")]
        sandbox: bool,
        /// Force disable kernel filesystem sandbox (Landlock).
        #[arg(long, conflicts_with = "sandbox")]
        no_sandbox: bool,
    },
    /// Start a session (transition Idle → Starting → Working).
    Start {
        /// Session ID.
        session_id: String,
    },
    /// Create and immediately start a session.
    Run {
        /// Task description for the agent (required unless --template is specified).
        #[arg(short, long, required_unless_present = "template")]
        task: Option<String>,
        /// Optional template name or ID to configure the session.
        #[arg(long)]
        template: Option<String>,
        /// Agent type (default: agy).
        #[arg(short, long, default_value = "agy")]
        agent_type: String,
        /// Optional project ID.
        #[arg(long)]
        project_id: Option<String>,
        /// Optional explicit account ID.
        #[arg(long)]
        account_id: Option<String>,
        /// Optional conversation ID to resume.
        #[arg(short = 'c', long = "conversation")]
        conversation: Option<String>,
        /// Force enable kernel filesystem sandbox (Landlock).
        #[arg(long, conflicts_with = "no_sandbox")]
        sandbox: bool,
        /// Force disable kernel filesystem sandbox (Landlock).
        #[arg(long, conflicts_with = "sandbox")]
        no_sandbox: bool,
    },
    /// Pause a running session.
    Pause {
        /// Session ID.
        session_id: String,
    },
    /// Resume a paused session (or restart a stopped/crashed session).
    Resume {
        /// Session ID.
        session_id: String,
    },
    /// Stop a session.
    Stop {
        /// Session ID.
        session_id: String,
        /// Optional reason for stopping.
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Remove/delete a session permanently.
    #[command(alias = "delete")]
    Remove {
        /// Session ID.
        session_id: String,
    },
    /// Discover existing Antigravity conversations across host and account profiles.
    Discover,
    /// List all sessions.
    List,
    /// Get details for a specific session.
    Get {
        /// Session ID.
        session_id: String,
    },
    /// Steer a running session by injecting a human instruction.
    Steer {
        /// Session ID.
        session_id: String,
        /// Message/instruction to inject.
        #[arg(short, long)]
        message: String,
    },
    /// Explicitly select an account for an Idle session.
    SelectAccount {
        /// Session ID.
        session_id: String,
        /// Account ID.
        account_id: String,
    },
    /// Switch account for a session (Idle rebind or running hand-off/dynamic).
    SwitchAccount {
        /// Session ID.
        session_id: String,
        /// Target account ID.
        account_id: String,
    },
    /// Capture a safe session snapshot.
    Snapshot {
        /// Session ID.
        session_id: String,
    },
    /// Controlled session hand-off to another account.
    Handoff {
        /// Session ID.
        session_id: String,
        /// Optional target account ID.
        #[arg(short, long)]
        account_id: Option<String>,
    },
}

/// Account management subcommands.
#[derive(Subcommand)]
enum AccountCmd {
    /// Register a new provider account.
    Register {
        #[arg(short, long)]
        label: String,
        #[arg(short, long)]
        provider: String,
        /// Comma-separated list of agent types this account supports.
        #[arg(long, default_value = "agy")]
        agent_types: String,
        /// Reference key in the credential store (not a raw secret).
        #[arg(long, default_value = "ref:none")]
        credential_ref: String,
        /// Maximum concurrent sessions.
        #[arg(long, default_value = "2")]
        concurrency_cap: u8,
        /// Comma-separated tags for grouping/filtering.
        #[arg(long, default_value = "")]
        tags: String,
    },
    /// List all accounts.
    List,
    /// Query account availability for an agent type and optional tags.
    Availability {
        /// Agent type (e.g. agy, claude, pty).
        #[arg(short, long)]
        agent_type: Option<String>,
        /// Comma-separated tags.
        #[arg(long, default_value = "")]
        tags: String,
    },
    /// Get details for an account.
    Get { account_id: String },
    /// Disable an account (take it out of rotation).
    Disable { account_id: String },
    /// Re-enable a disabled account.
    Enable { account_id: String },
    /// Remove an account (only if it has no active sessions).
    /// Accepts an exact account ID or an unambiguous exact account name.
    Remove {
        account: String,
        /// Skip the confirmation prompt.
        #[arg(short, long)]
        yes: bool,
    },
    /// Add a new Antigravity account.
    Add {
        /// Optional friendly label for the account.
        #[arg(short, long)]
        name: Option<String>,
        /// Don't open a browser: print the login URL and paste the redirect URL back.
        #[arg(long)]
        cli: bool,
    },
    /// Log in to an account (alias for add).
    Login {
        /// Optional friendly label for the account.
        #[arg(short, long)]
        name: Option<String>,
        /// Don't open a browser: print the login URL and paste the redirect URL back.
        #[arg(long)]
        cli: bool,
    },
}

/// Project management subcommands.
#[derive(Subcommand)]
enum ProjectCmd {
    /// Register a new project.
    Register {
        #[arg(short, long)]
        name: String,
        #[arg(short, long)]
        repo_path: String,
        /// Default agent type for sessions in this project.
        #[arg(long)]
        default_agent_type: Option<String>,
        /// Comma-separated default account tags.
        #[arg(long, default_value = "")]
        default_account_tags: String,
        /// Workspace policy: shared or worktree_per_session.
        #[arg(long, default_value = "shared")]
        workspace_policy: String,
    },
    /// List all projects.
    List,
    /// Get details for a project.
    Get { project_id: String },
    /// Remove a project (only if no active sessions).
    Remove { project_id: String },
    /// List workspaces for a project.
    Workspaces { project_id: String },
}

/// Interaction management subcommands (Phase 3).
#[derive(Subcommand)]
enum InteractionCmd {
    /// List pending interactions awaiting decision or input.
    ListPending {
        /// Optional session ID filter.
        #[arg(short, long)]
        session_id: Option<String>,
    },
    /// List interactions with optional filters.
    List {
        /// Optional session ID filter.
        #[arg(short, long)]
        session_id: Option<String>,
        /// Optional state filter (pending, auto_resolved, human_resolved, dismissed, expired).
        #[arg(long)]
        state: Option<String>,
    },
    /// Get details of a specific interaction.
    Get {
        /// Interaction ID.
        interaction_id: String,
    },
    /// Reply to an interaction (question or approval).
    Reply {
        /// Interaction ID.
        interaction_id: String,
        /// Decision for approval requests: "allow" or "deny".
        #[arg(short, long)]
        decision: Option<String>,
        /// Text response for questions or rationale.
        #[arg(short, long)]
        response: Option<String>,
        /// Actor identity (default: human).
        #[arg(long)]
        actor: Option<String>,
    },
    /// Approve an interaction directly.
    Approve {
        /// Interaction ID.
        interaction_id: String,
        /// Optional response note.
        #[arg(short, long)]
        note: Option<String>,
    },
    /// Deny an interaction directly.
    Deny {
        /// Interaction ID.
        interaction_id: String,
        /// Optional denial reason.
        #[arg(short, long)]
        reason: Option<String>,
    },
    /// Dismiss an interaction without a decision.
    Dismiss {
        /// Interaction ID.
        interaction_id: String,
        /// Actor identity.
        #[arg(long)]
        actor: Option<String>,
    },
}

/// Policy management subcommands (Phase 3).
#[derive(Subcommand)]
enum PolicyCmd {
    /// List policy rules.
    List {
        /// Optional scope filter ("global" or "project:<id>").
        #[arg(short, long)]
        scope: Option<String>,
    },
    /// Get details of a specific policy rule.
    Get {
        /// Policy ID.
        policy_id: String,
    },
    /// Create or update a policy rule.
    Upsert {
        /// Policy ID (if updating existing).
        #[arg(long)]
        policy_id: Option<String>,
        /// Policy rule name.
        #[arg(short, long)]
        name: String,
        /// Scope: "global" or "project:<id>".
        #[arg(short, long, default_value = "global")]
        scope: String,
        /// Priority (higher evaluates first).
        #[arg(short, long, default_value = "0")]
        priority: i32,
        /// Decision: "allow", "deny", or "require_human".
        #[arg(short, long)]
        decision: String,
        /// JSON array of conditions (e.g. '[{"tool_name_equals":"read_file"}]').
        #[arg(short, long, default_value = "[]")]
        conditions: String,
        /// Whether this policy is disabled.
        #[arg(long)]
        disabled: bool,
    },
    /// Remove a policy rule.
    Remove {
        /// Policy ID.
        policy_id: String,
    },
    /// Test policy evaluation without applying it.
    Test {
        /// Tool name to test.
        #[arg(short, long)]
        tool_name: Option<String>,
        /// Agent type to test.
        #[arg(short, long)]
        agent_type: Option<String>,
        /// Project ID to test.
        #[arg(short, long)]
        project_id: Option<String>,
    },
}

/// Audit log subcommands (Phase 3).
#[derive(Subcommand)]
enum AuditCmd {
    /// List audit log entries.
    List {
        /// Optional session ID filter.
        #[arg(short, long)]
        session_id: Option<String>,
        /// Maximum number of entries to return.
        #[arg(short, long, default_value = "50")]
        limit: u64,
    },
}

#[derive(Subcommand)]
enum EventsCmd {
    /// Query events from the event log (not yet implemented in daemon).
    Query {
        /// Filter by session ID.
        #[arg(long)]
        session_id: Option<String>,
        /// Maximum number of events to return.
        #[arg(long, default_value = "50")]
        limit: u64,
    },
    /// Stream live events from the daemon.
    Subscribe,
    /// Verify sequence integrity and continuity of the event store (Phase 8).
    Verify {
        /// Optional path to SQLite database (defaults to daemon config path).
        #[arg(long)]
        db: Option<PathBuf>,
    },
    /// Replay and validate event log against the state machine (Phase 8).
    Replay {
        /// Optional path to SQLite database (defaults to daemon config path).
        #[arg(long)]
        db: Option<PathBuf>,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if matches!(cli.command, Commands::Tui | Commands::Dashboard) {
        return ac_tui::run_tui(cli.socket).await;
    }

    if let Commands::Doctor { deep, json } = cli.command {
        let code = ac_cli::doctor::run_doctor(ac_core::doctor::DoctorOpts {
            deep,
            json: json || cli.json,
            socket_path: Some(cli.socket),
            ..Default::default()
        })
        .await?;
        std::process::exit(code);
    }

    if let Commands::Login {
        ref name,
        cli: cli_mode,
    } = cli.command
    {
        let client = ac_cli::client::DaemonClient::new(cli.socket);
        client.ensure_daemon_running().await?;
        ac_cli::auth::run_add_account_flow(&client, name.clone(), cli_mode).await?;
        return Ok(());
    }

    if let Commands::Account(
        AccountCmd::Add {
            ref name,
            cli: cli_mode,
        }
        | AccountCmd::Login {
            ref name,
            cli: cli_mode,
        },
    ) = cli.command
    {
        let client = ac_cli::client::DaemonClient::new(cli.socket);
        client.ensure_daemon_running().await?;
        ac_cli::auth::run_add_account_flow(&client, name.clone(), cli_mode).await?;
        return Ok(());
    }

    if let Commands::Account(AccountCmd::Remove { ref account, yes }) = cli.command {
        let client = ac_cli::client::DaemonClient::new(cli.socket);
        client.ensure_daemon_running().await?;
        return ac_cli::launcher::remove_account_command(&client, account, yes).await;
    }

    if let Commands::Events(EventsCmd::Verify { ref db }) = cli.command {
        let db_path = match db {
            Some(p) => p.clone(),
            None => ac_core::config::Config::default().db_path,
        };
        let store = ac_core::event_store::EventStore::open(&db_path)?;
        let report = store.verify_integrity()?;
        if cli.json {
            println!("{}", serde_json::to_string(&report)?);
        } else {
            println!("Event Store Integrity Report:");
            println!("  Database:        {}", db_path.display());
            println!("  Schema Version:  {}", report.schema_version);
            println!("  Total Events:    {}", report.total_events);
            println!("  Max Sequence:    {}", report.max_seq);
            println!("  Gaps Detected:   {}", report.gap_count);
            println!(
                "  Status:          {}",
                if report.is_valid {
                    "VALID"
                } else {
                    "CORRUPTED"
                }
            );
        }
        if !report.is_valid {
            std::process::exit(1);
        }
        return Ok(());
    }

    if let Commands::Events(EventsCmd::Replay { ref db }) = cli.command {
        let db_path = match db {
            Some(p) => p.clone(),
            None => ac_core::config::Config::default().db_path,
        };
        let start = std::time::Instant::now();
        let store = ac_core::event_store::EventStore::open(&db_path)?;
        let total_events = store.max_seq()?;
        let (event_tx, _) = tokio::sync::broadcast::channel(16);
        let (_cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(16);
        let adapter_factory = Box::new(ac_core::adapter::CompositeAdapterFactory::new());
        let mut mgr = ac_core::session::manager::SessionManager::new(
            store,
            cmd_rx,
            event_tx,
            3,
            adapter_factory,
        );
        mgr.recover_from_store()?;
        let elapsed = start.elapsed();
        let sessions = mgr.sessions();
        if cli.json {
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "events_replayed": total_events,
                    "sessions_reconstructed": sessions.len(),
                    "duration_ms": elapsed.as_millis(),
                    "success": true
                }))?
            );
        } else {
            println!("Event Store Replay Report:");
            println!("  Database:               {}", db_path.display());
            println!("  Events Replayed:        {}", total_events);
            println!("  Sessions Reconstructed: {}", sessions.len());
            println!("  Duration:               {:?}", elapsed);
            println!("  Status:                 SUCCESS");
        }
        return Ok(());
    }

    let (cmd, params) = build_request(&cli.command)?;

    if cmd == "events.subscribe" {
        // Streaming: print each event line as it arrives
        subscribe_events(&cli.socket).await?;
        return Ok(());
    }

    if cmd == "session.create_from_template" && params.get("task_description").is_none() {
        if let Some(tmpl_name) = params.get("template").and_then(|v| v.as_str()) {
            let check_resp = send_command(&cli.socket, "template.get", json!({ "template": tmpl_name })).await?;
            if !check_resp.ok {
                if cli.json {
                    println!("{}", serde_json::to_string(&check_resp)?);
                } else {
                    let err = check_resp
                        .error
                        .map(|e| format!("{}: {}", e.code, e.message))
                        .unwrap_or_else(|| "Template not found".into());
                    eprintln!("Error [{}]", err);
                }
                std::process::exit(1);
            }
            if let Some(tmpl) = check_resp.result.as_ref().and_then(|r| r.get("template")) {
                let prompt = tmpl
                    .get("default_task_prompt")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .trim();
                if prompt.is_empty() {
                    if cli.json {
                        let err_resp = json!({
                            "v": 1,
                            "ok": false,
                            "error": {
                                "code": "ValidationError",
                                "message": format!("Template '{tmpl_name}' has no default task prompt; specify --task <TASK>")
                            }
                        });
                        println!("{}", serde_json::to_string(&err_resp)?);
                    } else {
                        eprintln!("Error [ValidationError]: Template '{tmpl_name}' has no default task prompt; specify --task <TASK>");
                    }
                    std::process::exit(1);
                }
            }
        }
    }

    let resp = send_command(&cli.socket, &cmd, params).await?;

    let plain = cli.plain || !std::io::stdout().is_terminal();

    let is_json = cli.json || matches!(&cli.command, Commands::Metrics { json: true, .. });

    if is_json {
        if cmd == "metrics.get" && resp.ok {
            if let Some(metrics) = resp.result.as_ref().and_then(|r| r.get("metrics")) {
                println!("{}", serde_json::to_string_pretty(metrics)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&resp)?);
            }
        } else if cmd == "session.get" && resp.ok {
            if let Some(serde_json::Value::Object(mut map)) = resp.result.clone() {
                map.insert("ok".into(), json!(true));
                map.insert("v".into(), json!(resp.v));
                map.insert("result".into(), resp.result.clone().unwrap_or(serde_json::Value::Null));
                println!("{}", serde_json::to_string(&serde_json::Value::Object(map))?);
            } else {
                println!("{}", serde_json::to_string(&resp)?);
            }
        } else {
            println!("{}", serde_json::to_string(&resp)?);
        }
    } else {
        print_response(&resp, plain);
    }

    if !resp.ok {
        std::process::exit(1);
    }

    Ok(())
}

fn build_request(commands: &Commands) -> Result<(String, serde_json::Value)> {
    let (cmd, params) = match commands {
        Commands::Status => ("daemon.status".to_owned(), json!({})),
        Commands::Metrics { .. } => ("metrics.get".to_owned(), json!({})),
        Commands::Notification(n) => match n {
            NotificationCmd::Status => ("notification.status".to_owned(), json!({})),
            NotificationCmd::Test { channel, message } => (
                "notification.test".to_owned(),
                json!({
                    "channel": channel,
                    "message": message,
                }),
            ),
        },
        Commands::Tui | Commands::Dashboard | Commands::Login { .. } | Commands::Doctor { .. } => {
            unreachable!()
        }

        Commands::Session(s) => match s {
            SessionCmd::Create {
                task,
                agent_type,
                project_id,
                account_id,
                conversation,
                sandbox,
                no_sandbox,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("task_description".into(), json!(task));
                map.insert("agent_type".into(), json!(agent_type));
                map.insert("project_id".into(), json!(project_id));
                map.insert("account_id".into(), json!(account_id));
                let mut launch_map = serde_json::Map::new();
                if let Some(cid) = conversation {
                    map.insert("conversation_id".into(), json!(cid));
                    launch_map.insert("conversation_id".into(), json!(cid));
                }
                if *sandbox {
                    map.insert("sandbox".into(), json!(true));
                    launch_map.insert("sandbox".into(), json!(true));
                } else if *no_sandbox {
                    map.insert("sandbox".into(), json!(false));
                    launch_map.insert("sandbox".into(), json!(false));
                }
                if !launch_map.is_empty() {
                    map.insert("launch".into(), serde_json::Value::Object(launch_map));
                }
                ("session.create".to_owned(), serde_json::Value::Object(map))
            }
            SessionCmd::Start { session_id } => (
                "session.start".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Run {
                task,
                template,
                agent_type,
                project_id,
                account_id,
                conversation,
                sandbox,
                no_sandbox,
            } => {
                if let Some(tmpl) = template {
                    let mut map = serde_json::Map::new();
                    map.insert("template".into(), json!(tmpl));
                    if let Some(t) = task {
                        map.insert("task_description".into(), json!(t));
                    }
                    if let Some(pid) = project_id {
                        map.insert("project_id".into(), json!(pid));
                    }
                    if let Some(aid) = account_id {
                        map.insert("account_id".into(), json!(aid));
                    }
                    let mut launch_map = serde_json::Map::new();
                    if let Some(cid) = conversation {
                        map.insert("conversation_id".into(), json!(cid));
                        launch_map.insert("conversation_id".into(), json!(cid));
                    }
                    if *sandbox {
                        map.insert("sandbox".into(), json!(true));
                        launch_map.insert("sandbox".into(), json!(true));
                    } else if *no_sandbox {
                        map.insert("sandbox".into(), json!(false));
                        launch_map.insert("sandbox".into(), json!(false));
                    }
                    if !launch_map.is_empty() {
                        map.insert("launch".into(), serde_json::Value::Object(launch_map));
                    }
                    map.insert("start".into(), json!(true));
                    (
                        "session.create_from_template".to_owned(),
                        serde_json::Value::Object(map),
                    )
                } else {
                    let mut map = serde_json::Map::new();
                    map.insert(
                        "task_description".into(),
                        json!(task.as_deref().unwrap_or_default()),
                    );
                    map.insert("agent_type".into(), json!(agent_type));
                    map.insert("project_id".into(), json!(project_id));
                    map.insert("account_id".into(), json!(account_id));
                    let mut launch_map = serde_json::Map::new();
                    if let Some(cid) = conversation {
                        map.insert("conversation_id".into(), json!(cid));
                        launch_map.insert("conversation_id".into(), json!(cid));
                    }
                    if *sandbox {
                        map.insert("sandbox".into(), json!(true));
                        launch_map.insert("sandbox".into(), json!(true));
                    } else if *no_sandbox {
                        map.insert("sandbox".into(), json!(false));
                        launch_map.insert("sandbox".into(), json!(false));
                    }
                    if !launch_map.is_empty() {
                        map.insert("launch".into(), serde_json::Value::Object(launch_map));
                    }
                    (
                        "session.create_and_start".to_owned(),
                        serde_json::Value::Object(map),
                    )
                }
            }
            SessionCmd::Pause { session_id } => (
                "session.pause".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Resume { session_id } => (
                "session.resume".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Stop { session_id, reason } => (
                "session.stop".to_owned(),
                json!({ "session_id": session_id, "reason": reason }),
            ),
            SessionCmd::Remove { session_id } => (
                "session.remove".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Discover => ("session.discover".to_owned(), json!({})),
            SessionCmd::List => ("session.list".to_owned(), json!({})),
            SessionCmd::Get { session_id } => (
                "session.get".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Steer {
                session_id,
                message,
            } => (
                "session.steer".to_owned(),
                json!({ "session_id": session_id, "message": message }),
            ),
            SessionCmd::SelectAccount {
                session_id,
                account_id,
            } => (
                "session.select_account".to_owned(),
                json!({ "session_id": session_id, "account_id": account_id }),
            ),
            SessionCmd::SwitchAccount {
                session_id,
                account_id,
            } => (
                "session.switch_account".to_owned(),
                json!({ "session_id": session_id, "target_account_id": account_id }),
            ),
            SessionCmd::Snapshot { session_id } => (
                "session.snapshot".to_owned(),
                json!({ "session_id": session_id }),
            ),
            SessionCmd::Handoff {
                session_id,
                account_id,
            } => (
                "session.handoff".to_owned(),
                json!({ "session_id": session_id, "target_account_id": account_id }),
            ),
        },

        Commands::Template(t) => match t {
            TemplateCmd::List => ("template.list".to_owned(), json!({})),
            TemplateCmd::Get { template } => (
                "template.get".to_owned(),
                json!({ "template": template }),
            ),
            TemplateCmd::Delete { template } => (
                "template.delete".to_owned(),
                json!({ "template": template }),
            ),
            TemplateCmd::Create {
                name,
                description,
                agent_type,
                prompt,
                model,
                permission_mode,
                account_tag,
                execution_mode,
                sandbox,
                working_dir,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("name".into(), json!(name));
                map.insert("agent_type".into(), json!(agent_type));
                if let Some(d) = description {
                    map.insert("description".into(), json!(d));
                }
                if let Some(p) = prompt {
                    map.insert("default_task_prompt".into(), json!(p));
                }
                if let Some(m) = model.as_ref() {
                    map.insert("model".into(), json!(m));
                }
                if let Some(pm) = permission_mode.as_ref() {
                    map.insert("permission_mode".into(), json!(pm));
                }
                if let Some(tag) = account_tag {
                    map.insert("account_tag".into(), json!(tag));
                }
                if let Some(wd) = working_dir.as_ref() {
                    map.insert("working_dir".into(), json!(wd));
                }

                let mut launch = serde_json::Map::new();
                if let Some(em) = execution_mode {
                    launch.insert("execution_mode".into(), json!(em));
                }
                if *sandbox {
                    launch.insert("sandbox".into(), json!(true));
                }
                if let Some(wd) = working_dir {
                    launch.insert("working_dir".into(), json!(wd));
                }
                if let Some(pm) = permission_mode {
                    launch.insert("permission_mode".into(), json!(pm));
                }
                if let Some(m) = model {
                    launch.insert("model".into(), json!(m));
                }
                if !launch.is_empty() {
                    map.insert("launch".into(), serde_json::Value::Object(launch));
                }

                ("template.create".to_owned(), serde_json::Value::Object(map))
            }
            TemplateCmd::Run {
                template,
                task,
                project_id,
                account_id,
                conversation,
            } => {
                let mut map = serde_json::Map::new();
                map.insert("template".into(), json!(template));
                if let Some(t) = task {
                    map.insert("task_description".into(), json!(t));
                }
                if let Some(pid) = project_id {
                    map.insert("project_id".into(), json!(pid));
                }
                if let Some(aid) = account_id {
                    map.insert("account_id".into(), json!(aid));
                }
                if let Some(cid) = conversation {
                    map.insert("conversation_id".into(), json!(cid));
                    map.insert("launch".into(), json!({ "conversation_id": cid }));
                }
                map.insert("start".into(), json!(true));
                (
                    "session.create_from_template".to_owned(),
                    serde_json::Value::Object(map),
                )
            }
        },

        Commands::Conversation(c) => match c {
            ConversationCmd::List => ("conversation.list".to_owned(), json!({})),
        },

        Commands::Account(a) => match a {
            AccountCmd::Register {
                label,
                provider,
                agent_types,
                credential_ref,
                concurrency_cap,
                tags,
            } => {
                let agent_types_vec: Vec<&str> = agent_types.split(',').map(str::trim).collect();
                let tags_vec: Vec<&str> = if tags.is_empty() {
                    vec![]
                } else {
                    tags.split(',').map(str::trim).collect()
                };
                (
                    "account.register".to_owned(),
                    json!({
                        "label": label,
                        "provider": provider,
                        "agent_types": agent_types_vec,
                        "credential_ref": credential_ref,
                        "concurrency_cap": concurrency_cap,
                        "tags": tags_vec,
                    }),
                )
            }
            AccountCmd::List => ("account.list".to_owned(), json!({})),
            AccountCmd::Availability { agent_type, tags } => {
                let tags_vec: Vec<&str> = if tags.is_empty() {
                    vec![]
                } else {
                    tags.split(',').map(str::trim).collect()
                };
                (
                    "account.query_availability".to_owned(),
                    json!({
                        "agent_type": agent_type,
                        "tags": tags_vec,
                    }),
                )
            }
            AccountCmd::Get { account_id } => (
                "account.get".to_owned(),
                json!({ "account_id": account_id }),
            ),
            AccountCmd::Disable { account_id } => (
                "account.disable".to_owned(),
                json!({ "account_id": account_id }),
            ),
            AccountCmd::Enable { account_id } => (
                "account.enable".to_owned(),
                json!({ "account_id": account_id }),
            ),
            AccountCmd::Add { .. } | AccountCmd::Login { .. } | AccountCmd::Remove { .. } => {
                unreachable!()
            }
        },

        Commands::Project(p) => match p {
            ProjectCmd::Register {
                name,
                repo_path,
                default_agent_type,
                default_account_tags,
                workspace_policy,
            } => {
                let tags_vec: Vec<&str> = if default_account_tags.is_empty() {
                    vec![]
                } else {
                    default_account_tags.split(',').map(str::trim).collect()
                };
                (
                    "project.register".to_owned(),
                    json!({
                        "name": name,
                        "repo_path": repo_path,
                        "default_agent_type": default_agent_type,
                        "default_account_tags": tags_vec,
                        "workspace_policy": workspace_policy,
                    }),
                )
            }
            ProjectCmd::List => ("project.list".to_owned(), json!({})),
            ProjectCmd::Get { project_id } => (
                "project.get".to_owned(),
                json!({ "project_id": project_id }),
            ),
            ProjectCmd::Remove { project_id } => (
                "project.remove".to_owned(),
                json!({ "project_id": project_id }),
            ),
            ProjectCmd::Workspaces { project_id } => (
                "project.workspaces".to_owned(),
                json!({ "project_id": project_id }),
            ),
        },

        Commands::Interaction(i) => match i {
            InteractionCmd::ListPending { session_id } => (
                "interaction.list_pending".to_owned(),
                json!({ "session_id": session_id }),
            ),
            InteractionCmd::List { session_id, state } => (
                "interaction.list".to_owned(),
                json!({ "session_id": session_id, "state": state }),
            ),
            InteractionCmd::Get { interaction_id } => (
                "interaction.get".to_owned(),
                json!({ "interaction_id": interaction_id }),
            ),
            InteractionCmd::Reply {
                interaction_id,
                decision,
                response,
                actor,
            } => (
                "interaction.reply".to_owned(),
                json!({
                    "interaction_id": interaction_id,
                    "decision": decision,
                    "response": response,
                    "actor": actor,
                }),
            ),
            InteractionCmd::Approve {
                interaction_id,
                note,
            } => (
                "interaction.reply".to_owned(),
                json!({
                    "interaction_id": interaction_id,
                    "decision": "allow",
                    "response": note,
                }),
            ),
            InteractionCmd::Deny {
                interaction_id,
                reason,
            } => (
                "interaction.reply".to_owned(),
                json!({
                    "interaction_id": interaction_id,
                    "decision": "deny",
                    "response": reason,
                }),
            ),
            InteractionCmd::Dismiss {
                interaction_id,
                actor,
            } => (
                "interaction.dismiss".to_owned(),
                json!({
                    "interaction_id": interaction_id,
                    "actor": actor,
                }),
            ),
        },

        Commands::Policy(p) => match p {
            PolicyCmd::List { scope } => ("policy.list".to_owned(), json!({ "scope": scope })),
            PolicyCmd::Get { policy_id } => {
                ("policy.get".to_owned(), json!({ "policy_id": policy_id }))
            }
            PolicyCmd::Upsert {
                policy_id,
                name,
                scope,
                priority,
                decision,
                conditions,
                disabled,
            } => {
                let conditions_val: serde_json::Value =
                    serde_json::from_str(conditions).unwrap_or(json!([]));
                (
                    "policy.upsert".to_owned(),
                    json!({
                        "policy_id": policy_id,
                        "name": name,
                        "scope": scope,
                        "priority": priority,
                        "decision": decision,
                        "conditions": conditions_val,
                        "enabled": !disabled,
                    }),
                )
            }
            PolicyCmd::Remove { policy_id } => (
                "policy.remove".to_owned(),
                json!({ "policy_id": policy_id }),
            ),
            PolicyCmd::Test {
                tool_name,
                agent_type,
                project_id,
            } => (
                "policy.test".to_owned(),
                json!({
                    "tool_name": tool_name,
                    "agent_type": agent_type,
                    "project_id": project_id,
                }),
            ),
        },

        Commands::Audit(a) => match a {
            AuditCmd::List { session_id, limit } => (
                "audit.list".to_owned(),
                json!({ "session_id": session_id, "limit": limit }),
            ),
        },

        Commands::Events(e) => match e {
            EventsCmd::Query { session_id, limit } => (
                "events.query".to_owned(),
                json!({ "session_id": session_id, "limit": limit }),
            ),
            EventsCmd::Subscribe => ("events.subscribe".to_owned(), json!({})),
            EventsCmd::Verify { .. } | EventsCmd::Replay { .. } => unreachable!(),
        },
    };
    Ok((cmd, params))
}

// ── Socket helpers ────────────────────────────────────────────────────────────

async fn send_command(
    socket_path: &PathBuf,
    cmd: &str,
    params: serde_json::Value,
) -> Result<ApiResponse> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to daemon socket: {}", socket_path.display()))?;

    let (read_half, mut write_half) = stream.into_split();

    let req = ApiRequest {
        v: 1,
        id: "cli-1".to_owned(),
        cmd: cmd.to_owned(),
        params,
    };

    let line = serde_json::to_string(&req)? + "\n";
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

async fn subscribe_events(socket_path: &PathBuf) -> Result<()> {
    let stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to {}", socket_path.display()))?;

    let (read_half, mut write_half) = stream.into_split();

    let req = ApiRequest {
        v: 1,
        id: "cli-sub".to_owned(),
        cmd: "events.subscribe".to_owned(),
        params: json!({}),
    };
    let line = serde_json::to_string(&req)? + "\n";
    write_half.write_all(line.as_bytes()).await?;

    println!("Subscribed to event stream (Ctrl-C to stop)...");

    let reader = BufReader::new(read_half);
    let mut lines = reader.lines();
    while let Some(line) = lines.next_line().await? {
        // Pretty-print events
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            println!("{line}");
        }
    }
    Ok(())
}

// ── Output formatting ─────────────────────────────────────────────────────────

fn print_response(resp: &ApiResponse, plain: bool) {
    if resp.ok {
        if let Some(result) = &resp.result {
            // Metrics
            if let Some(prom) = result.get("prometheus").and_then(|p| p.as_str()) {
                print!("{}", prom);
                return;
            }

            // Sessions list
            if let Some(sessions) = result.get("sessions").and_then(|s| s.as_array()) {
                if sessions.is_empty() {
                    if !plain {
                        println!("No sessions.");
                    }
                    return;
                }
                if plain {
                    for s in sessions {
                        let is_ext = s["is_external"].as_bool().unwrap_or(false);
                        let ext_tag = if is_ext { "[EXT] " } else { "" };
                        println!(
                            "{}\t{}\t{}\t{}{}",
                            s["id"].as_str().unwrap_or("?"),
                            s["state"].as_str().unwrap_or("?"),
                            s["agent_type"].as_str().unwrap_or("?"),
                            ext_tag,
                            s["task_description"].as_str().unwrap_or("?"),
                        );
                    }
                    return;
                }
                println!(
                    "{:<26}  {:<12}  {:<20}  {}",
                    "SESSION ID", "STATE", "AGENT", "TASK"
                );
                println!("{}", "-".repeat(80));
                for s in sessions {
                    let is_ext = s["is_external"].as_bool().unwrap_or(false);
                    let ext_badge = if is_ext { " [EXT]" } else { "" };
                    let agent_str =
                        format!("{}{}", s["agent_type"].as_str().unwrap_or("?"), ext_badge);
                    println!(
                        "{:<26}  {:<12}  {:<20}  {}",
                        s["id"].as_str().unwrap_or("?"),
                        s["state"].as_str().unwrap_or("?"),
                        agent_str,
                        s["task_description"].as_str().unwrap_or("?"),
                    );
                }
                return;
            }
            // Templates list
            if let Some(templates) = result.get("templates").and_then(|t| t.as_array()) {
                if templates.is_empty() {
                    if !plain {
                        println!("No templates.");
                    }
                    return;
                }
                if plain {
                    for t in templates {
                        let id = t["id"].as_str().unwrap_or("?");
                        let name = t["name"].as_str().unwrap_or("?");
                        let agent = t["agent_type"].as_str().unwrap_or("?");
                        let model = t["model"].as_str().unwrap_or("");
                        let desc = t["description"]
                            .as_str()
                            .map(|s| s.replace(['\n', '\r', '\t'], " "))
                            .unwrap_or_default();
                        println!("{}\t{}\t{}\t{}\t{}", id, name, agent, model, desc);
                    }
                    return;
                }
                println!(
                    "{:<26}  {:<24}  {:<8}  {:<24}  {}",
                    "TEMPLATE ID", "NAME", "AGENT", "MODEL", "DESCRIPTION"
                );
                println!("{}", "-".repeat(100));
                for t in templates {
                    let id = t["id"].as_str().unwrap_or("?");
                    let name = t["name"].as_str().unwrap_or("?");
                    let agent = t["agent_type"].as_str().unwrap_or("?");
                    let model = t["model"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .unwrap_or("-");
                    let desc = t["description"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .map(|s| s.replace(['\n', '\r'], " "))
                        .unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<26}  {:<24}  {:<8}  {:<24}  {}",
                        id, name, agent, model, desc
                    );
                }
                return;
            }
            // Conversations list
            if let Some(conversations) = result.get("conversations").and_then(|c| c.as_array()) {
                if conversations.is_empty() {
                    if !plain {
                        println!("No conversations found.");
                    }
                    return;
                }
                if plain {
                    for c in conversations {
                        let is_ext = c["is_external"].as_bool().unwrap_or(false);
                        let source = if is_ext {
                            "external".to_string()
                        } else if let Some(aid) = c["account_id"].as_str() {
                            format!("profile ({aid})")
                        } else {
                            "profile".to_string()
                        };
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            c["conversation_id"].as_str().unwrap_or("?"),
                            source,
                            c["step_count"].as_u64().unwrap_or(0),
                            c["last_modified_time"].as_str().unwrap_or("?"),
                            c["title"].as_str().unwrap_or("?"),
                        );
                    }
                    return;
                }
                println!(
                    "{:<38}  {:<24}  {:<6}  {:<22}  {}",
                    "CONVERSATION ID", "SOURCE", "STEPS", "LAST MODIFIED", "TITLE"
                );
                println!("{}", "-".repeat(110));
                for c in conversations {
                    let is_ext = c["is_external"].as_bool().unwrap_or(false);
                    let source = if is_ext {
                        "external".to_string()
                    } else if let Some(aid) = c["account_id"].as_str() {
                        format!("profile ({aid})")
                    } else {
                        "profile".to_string()
                    };
                    println!(
                        "{:<38}  {:<24}  {:<6}  {:<22}  {}",
                        c["conversation_id"].as_str().unwrap_or("?"),
                        source,
                        c["step_count"].as_u64().unwrap_or(0),
                        c["last_modified_time"].as_str().unwrap_or("?"),
                        c["title"].as_str().unwrap_or("?"),
                    );
                }
                return;
            }
            // Accounts list
            if let Some(accounts) = result.get("accounts").and_then(|a| a.as_array()) {
                if accounts.is_empty() {
                    if !plain {
                        println!("No accounts.");
                    }
                    return;
                }
                if plain {
                    for a in accounts {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            a["id"]
                                .as_str()
                                .or_else(|| a["account_id"].as_str())
                                .unwrap_or("?"),
                            a["state"].as_str().unwrap_or("?"),
                            a["provider"].as_str().unwrap_or("?"),
                            a["concurrency_cap"].as_u64().unwrap_or(0),
                            a["label"].as_str().unwrap_or("?"),
                        );
                    }
                    return;
                }
                println!(
                    "{:<26}  {:<12}  {:<14}  {:<4}  {}",
                    "ACCOUNT ID", "STATE", "PROVIDER", "CAP", "LABEL"
                );
                println!("{}", "-".repeat(80));
                for a in accounts {
                    println!(
                        "{:<26}  {:<12}  {:<14}  {:<4}  {}",
                        a["id"]
                            .as_str()
                            .or_else(|| a["account_id"].as_str())
                            .unwrap_or("?"),
                        a["state"].as_str().unwrap_or("?"),
                        a["provider"].as_str().unwrap_or("?"),
                        a["concurrency_cap"].as_u64().unwrap_or(0),
                        a["label"].as_str().unwrap_or("?"),
                    );
                }
                return;
            }
            // Projects list
            if let Some(projects) = result.get("projects").and_then(|p| p.as_array()) {
                if projects.is_empty() {
                    if !plain {
                        println!("No projects.");
                    }
                    return;
                }
                if plain {
                    for p in projects {
                        println!(
                            "{}\t{}\t{}",
                            p["id"].as_str().unwrap_or("?"),
                            p["name"].as_str().unwrap_or("?"),
                            p["repo_path"].as_str().unwrap_or("?"),
                        );
                    }
                    return;
                }
                println!("{:<26}  {:<20}  {}", "PROJECT ID", "NAME", "REPO");
                println!("{}", "-".repeat(80));
                for p in projects {
                    println!(
                        "{:<26}  {:<20}  {}",
                        p["id"].as_str().unwrap_or("?"),
                        p["name"].as_str().unwrap_or("?"),
                        p["repo_path"].as_str().unwrap_or("?"),
                    );
                }
                return;
            }
            // Interactions list
            if let Some(interactions) = result.get("interactions").and_then(|i| i.as_array()) {
                if interactions.is_empty() {
                    if !plain {
                        println!("No interactions.");
                    }
                    return;
                }
                if plain {
                    for i in interactions {
                        let details = i["tool_name"]
                            .as_str()
                            .or_else(|| i["prompt"].as_str())
                            .unwrap_or("");
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            i["id"].as_str().unwrap_or("?"),
                            i["session_id"].as_str().unwrap_or("?"),
                            i["kind"].as_str().unwrap_or("?"),
                            i["state"].as_str().unwrap_or("?"),
                            details,
                        );
                    }
                    return;
                }
                println!(
                    "{:<26}  {:<26}  {:<16}  {:<14}  {}",
                    "INTERACTION ID", "SESSION ID", "KIND", "STATE", "DETAILS"
                );
                println!("{}", "-".repeat(100));
                for i in interactions {
                    let details = i["tool_name"]
                        .as_str()
                        .or_else(|| i["prompt"].as_str())
                        .unwrap_or("");
                    println!(
                        "{:<26}  {:<26}  {:<16}  {:<14}  {}",
                        i["id"].as_str().unwrap_or("?"),
                        i["session_id"].as_str().unwrap_or("?"),
                        i["kind"].as_str().unwrap_or("?"),
                        i["state"].as_str().unwrap_or("?"),
                        details,
                    );
                }
                return;
            }
            // Policies list
            if let Some(policies) = result.get("policies").and_then(|p| p.as_array()) {
                if policies.is_empty() {
                    if !plain {
                        println!("No policies.");
                    }
                    return;
                }
                if plain {
                    for p in policies {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            p["id"].as_str().unwrap_or("?"),
                            p["priority"].as_i64().unwrap_or(0),
                            p["decision"].as_str().unwrap_or("?"),
                            p["scope"].as_str().unwrap_or("?"),
                            p["name"].as_str().unwrap_or("?"),
                        );
                    }
                    return;
                }
                println!(
                    "{:<26}  {:<8}  {:<12}  {:<14}  {}",
                    "POLICY ID", "PRIORITY", "DECISION", "SCOPE", "NAME"
                );
                println!("{}", "-".repeat(80));
                for p in policies {
                    println!(
                        "{:<26}  {:<8}  {:<12}  {:<14}  {}",
                        p["id"].as_str().unwrap_or("?"),
                        p["priority"].as_i64().unwrap_or(0),
                        p["decision"].as_str().unwrap_or("?"),
                        p["scope"].as_str().unwrap_or("?"),
                        p["name"].as_str().unwrap_or("?"),
                    );
                }
                return;
            }
            // Audit entries list
            if let Some(entries) = result.get("audit_entries").and_then(|e| e.as_array()) {
                if entries.is_empty() {
                    if !plain {
                        println!("No audit entries.");
                    }
                    return;
                }
                if plain {
                    for e in entries {
                        println!(
                            "{}\t{}\t{}\t{}",
                            e["timestamp"].as_str().unwrap_or("?"),
                            e["actor"].as_str().unwrap_or("?"),
                            e["action"].as_str().unwrap_or("?"),
                            e["rationale"].as_str().unwrap_or(""),
                        );
                    }
                    return;
                }
                println!(
                    "{:<24}  {:<20}  {:<14}  {}",
                    "TIMESTAMP", "ACTOR", "ACTION", "RATIONALE"
                );
                println!("{}", "-".repeat(80));
                for e in entries {
                    println!(
                        "{:<24}  {:<20}  {:<14}  {}",
                        e["timestamp"].as_str().unwrap_or("?"),
                        e["actor"].as_str().unwrap_or("?"),
                        e["action"].as_str().unwrap_or("?"),
                        e["rationale"].as_str().unwrap_or(""),
                    );
                }
                return;
            }
            // Notification status (Feature F8)
            if let Some(status) = result.get("status").and_then(|s| s.as_object()) {
                if status.contains_key("discord_configured") || status.contains_key("metrics") {
                    print!("{}", render_notification_status(status, plain));
                    return;
                }
            }
            // Notification test results (Feature F8)
            if let Some(test_results) = result.get("test_results").and_then(|t| t.as_object()) {
                let channels = test_results
                    .get("channels")
                    .and_then(|c| c.as_array())
                    .cloned()
                    .unwrap_or_default();
                print!("{}", render_notification_test(&channels, plain));
                return;
            }
            println!(
                "{}",
                serde_json::to_string_pretty(result).unwrap_or_default()
            );
        } else {
            println!("OK");
        }
    } else if let Some(err) = &resp.error {
        eprintln!("Error [{}]: {}", err.code, err.message);
    }
}

fn render_notification_status(
    status: &serde_json::Map<String, serde_json::Value>,
    plain: bool,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let enabled = status.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let desktop = status.get("desktop").and_then(|v| v.as_bool()).unwrap_or(false);
    let discord = status.get("discord_configured").and_then(|v| v.as_bool()).unwrap_or(false);
    let slack = status.get("slack_configured").and_then(|v| v.as_bool()).unwrap_or(false);
    let generic_count = status.get("generic_webhooks_count").and_then(|v| v.as_u64()).unwrap_or(0);
    let events: Vec<String> = status
        .get("events")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|e| e.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let events_str = if events.is_empty() {
        "none".to_string()
    } else {
        events.join(", ")
    };

    let metrics = status.get("metrics");
    let total_dispatched = metrics.and_then(|m| m.get("total_dispatched")).and_then(|v| v.as_u64()).unwrap_or(0);
    let successful = metrics.and_then(|m| m.get("successful")).and_then(|v| v.as_u64()).unwrap_or(0);
    let failed = metrics.and_then(|m| m.get("failed")).and_then(|v| v.as_u64()).unwrap_or(0);
    let last_success = metrics.and_then(|m| m.get("last_success")).and_then(|v| v.as_str()).unwrap_or("Never");
    let last_error = metrics.and_then(|m| m.get("last_error")).and_then(|v| v.as_str()).unwrap_or("None");

    if plain {
        let _ = writeln!(out, "enabled\t{}", enabled);
        let _ = writeln!(out, "desktop\t{}", desktop);
        let _ = writeln!(out, "discord_configured\t{}", discord);
        let _ = writeln!(out, "slack_configured\t{}", slack);
        let _ = writeln!(out, "generic_webhooks_count\t{}", generic_count);
        let _ = writeln!(out, "events\t{}", events_str);
        let _ = writeln!(out, "total_dispatched\t{}", total_dispatched);
        let _ = writeln!(out, "successful\t{}", successful);
        let _ = writeln!(out, "failed\t{}", failed);
        let _ = writeln!(out, "last_success\t{}", last_success);
        let _ = writeln!(out, "last_error\t{}", last_error);
        return out;
    }

    let _ = writeln!(out, "Notification Configuration:");
    let _ = writeln!(out, "  Enabled:                {}", if enabled { "ENABLED" } else { "DISABLED" });
    let _ = writeln!(out, "  Desktop Notifications:  {}", if desktop { "ENABLED" } else { "DISABLED" });
    let _ = writeln!(out, "  Discord Webhook:        {}", if discord { "Configured" } else { "Not configured" });
    let _ = writeln!(out, "  Slack Webhook:          {}", if slack { "Configured" } else { "Not configured" });
    let _ = writeln!(out, "  Generic Webhooks:       {} configured", generic_count);
    let _ = writeln!(out, "  Events:                 {}", events_str);
    let _ = writeln!(out);
    let _ = writeln!(out, "Delivery Metrics:");
    let _ = writeln!(out, "  Total Dispatched:       {}", total_dispatched);
    let _ = writeln!(out, "  Successful:             {}", successful);
    let _ = writeln!(out, "  Failed:                 {}", failed);
    let _ = writeln!(out, "  Last Success:           {}", last_success);
    let _ = writeln!(out, "  Last Error:             {}", last_error);
    out
}

fn render_notification_test(channels: &[serde_json::Value], plain: bool) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    if channels.is_empty() {
        if !plain {
            out.push_str("No notification channels tested.\n");
        }
        return out;
    }

    if plain {
        for ch in channels {
            let channel = ch.get("channel").and_then(|v| v.as_str()).unwrap_or("?");
            let raw_status = ch.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let status_display = match raw_status.to_ascii_lowercase().as_str() {
                "success" => "SUCCESS",
                "failed" => "FAILED",
                "skipped" | "not_configured" => "NOT_CONFIGURED",
                _ => raw_status,
            };
            let details = ch.get("details").and_then(|v| v.as_str()).unwrap_or("-");
            let _ = writeln!(out, "{}\t{}\t{}", channel, status_display, details);
        }
        return out;
    }

    let _ = writeln!(out, "{:<14}  {:<16}  {}", "CHANNEL", "STATUS", "DETAILS");
    let _ = writeln!(out, "{}", "-".repeat(80));
    for ch in channels {
        let channel = ch.get("channel").and_then(|v| v.as_str()).unwrap_or("?");
        let raw_status = ch.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        let status_display = match raw_status.to_ascii_lowercase().as_str() {
            "success" => "SUCCESS",
            "failed" => "FAILED",
            "skipped" | "not_configured" => "NOT_CONFIGURED",
            _ => raw_status,
        };
        let details = ch.get("details").and_then(|v| v.as_str()).unwrap_or("-");
        let _ = writeln!(out, "{:<14}  {:<16}  {}", channel, status_display, details);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_cli_parse_notification_status() {
        let cli = Cli::try_parse_from(["ac", "notification", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notification(NotificationCmd::Status)
        ));
    }

    #[test]
    fn test_cli_parse_notify_alias_status() {
        let cli = Cli::try_parse_from(["ac", "notify", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Notification(NotificationCmd::Status)
        ));
    }

    #[test]
    fn test_cli_parse_notification_test_defaults() {
        let cli = Cli::try_parse_from(["ac", "notification", "test"]).unwrap();
        match cli.command {
            Commands::Notification(NotificationCmd::Test { channel, message }) => {
                assert_eq!(channel, None);
                assert_eq!(message, None);
            }
            _ => panic!("Expected NotificationCmd::Test"),
        }
    }

    #[test]
    fn test_cli_parse_notify_alias_test_with_args() {
        let cli = Cli::try_parse_from([
            "ac", "notify", "test", "-c", "discord", "-m", "Alert test",
        ])
        .unwrap();
        match cli.command {
            Commands::Notification(NotificationCmd::Test { channel, message }) => {
                assert_eq!(channel, Some("discord".to_string()));
                assert_eq!(message, Some("Alert test".to_string()));
            }
            _ => panic!("Expected NotificationCmd::Test"),
        }

        let cli2 = Cli::try_parse_from([
            "ac", "notify", "test", "--channel", "slack", "--message", "Long message",
        ])
        .unwrap();
        match cli2.command {
            Commands::Notification(NotificationCmd::Test { channel, message }) => {
                assert_eq!(channel, Some("slack".to_string()));
                assert_eq!(message, Some("Long message".to_string()));
            }
            _ => panic!("Expected NotificationCmd::Test"),
        }
    }

    #[test]
    fn test_build_request_notification_status() {
        let cmd = Commands::Notification(NotificationCmd::Status);
        let (name, params) = build_request(&cmd).unwrap();
        assert_eq!(name, "notification.status");
        assert_eq!(params, json!({}));
    }

    #[test]
    fn test_build_request_notification_test() {
        let cmd = Commands::Notification(NotificationCmd::Test {
            channel: Some("generic".to_string()),
            message: Some("hello generic".to_string()),
        });
        let (name, params) = build_request(&cmd).unwrap();
        assert_eq!(name, "notification.test");
        assert_eq!(
            params,
            json!({
                "channel": "generic",
                "message": "hello generic"
            })
        );

        let cmd_none = Commands::Notification(NotificationCmd::Test {
            channel: None,
            message: None,
        });
        let (name2, params2) = build_request(&cmd_none).unwrap();
        assert_eq!(name2, "notification.test");
        assert_eq!(
            params2,
            json!({
                "channel": null,
                "message": null
            })
        );
    }

    #[test]
    fn test_render_notification_status_pretty_and_plain() {
        let report = json!({
            "enabled": true,
            "desktop": false,
            "discord_configured": true,
            "slack_configured": false,
            "generic_webhooks_count": 2,
            "events": ["session_crashed", "session_finished"],
            "metrics": {
                "total_dispatched": 10,
                "successful": 9,
                "failed": 1,
                "last_success": "2026-11-18T10:00:00Z",
                "last_error": "HTTP 500"
            }
        });
        let map = report.as_object().unwrap();

        let pretty = render_notification_status(map, false);
        assert!(pretty.contains("Notification Configuration:"));
        assert!(pretty.contains("Enabled:                ENABLED"));
        assert!(pretty.contains("Desktop Notifications:  DISABLED"));
        assert!(pretty.contains("Discord Webhook:        Configured"));
        assert!(pretty.contains("Slack Webhook:          Not configured"));
        assert!(pretty.contains("Generic Webhooks:       2 configured"));
        assert!(pretty.contains("Events:                 session_crashed, session_finished"));
        assert!(pretty.contains("Delivery Metrics:"));
        assert!(pretty.contains("Total Dispatched:       10"));
        assert!(pretty.contains("Successful:             9"));
        assert!(pretty.contains("Failed:                 1"));
        assert!(pretty.contains("Last Success:           2026-11-18T10:00:00Z"));
        assert!(pretty.contains("Last Error:             HTTP 500"));

        let plain = render_notification_status(map, true);
        assert!(plain.contains("enabled\ttrue\n"));
        assert!(plain.contains("desktop\tfalse\n"));
        assert!(plain.contains("discord_configured\ttrue\n"));
        assert!(plain.contains("slack_configured\tfalse\n"));
        assert!(plain.contains("generic_webhooks_count\t2\n"));
        assert!(plain.contains("events\tsession_crashed, session_finished\n"));
        assert!(plain.contains("total_dispatched\t10\n"));
        assert!(plain.contains("successful\t9\n"));
        assert!(plain.contains("failed\t1\n"));
        assert!(plain.contains("last_success\t2026-11-18T10:00:00Z\n"));
        assert!(plain.contains("last_error\tHTTP 500\n"));
    }

    #[test]
    fn test_render_notification_test_pretty_and_plain() {
        let channels = vec![
            json!({
                "channel": "discord",
                "status": "success",
                "details": "HTTP 204 No Content"
            }),
            json!({
                "channel": "slack",
                "status": "skipped",
                "details": "Slack webhook URL not configured"
            }),
            json!({
                "channel": "desktop",
                "status": "failed",
                "details": "notify-send exited with code 1"
            }),
        ];

        let pretty = render_notification_test(&channels, false);
        assert!(pretty.contains("CHANNEL         STATUS            DETAILS"));
        assert!(pretty.contains("discord         SUCCESS           HTTP 204 No Content"));
        assert!(pretty.contains("slack           NOT_CONFIGURED    Slack webhook URL not configured"));
        assert!(pretty.contains("desktop         FAILED            notify-send exited with code 1"));

        let plain = render_notification_test(&channels, true);
        assert!(plain.contains("discord\tSUCCESS\tHTTP 204 No Content\n"));
        assert!(plain.contains("slack\tNOT_CONFIGURED\tSlack webhook URL not configured\n"));
        assert!(plain.contains("desktop\tFAILED\tnotify-send exited with code 1\n"));
    }

    #[test]
    fn test_cli_parse_session_create_sandbox_flags() {
        use clap::Parser;

        // --sandbox
        let cli = Cli::try_parse_from(["ac", "session", "create", "--task", "test", "--sandbox"])
            .expect("parse --sandbox");
        if let Commands::Session(SessionCmd::Create { sandbox, no_sandbox, .. }) = cli.command {
            assert!(sandbox);
            assert!(!no_sandbox);
        } else {
            panic!("expected SessionCmd::Create");
        }

        // --no-sandbox
        let cli = Cli::try_parse_from(["ac", "session", "create", "--task", "test", "--no-sandbox"])
            .expect("parse --no-sandbox");
        if let Commands::Session(SessionCmd::Create { sandbox, no_sandbox, .. }) = cli.command {
            assert!(!sandbox);
            assert!(no_sandbox);
        } else {
            panic!("expected SessionCmd::Create");
        }

        // mutual exclusivity
        assert!(Cli::try_parse_from(["ac", "session", "create", "--task", "test", "--sandbox", "--no-sandbox"]).is_err());
    }

    #[test]
    fn test_cli_parse_session_run_sandbox_flags() {
        use clap::Parser;

        // --sandbox
        let cli = Cli::try_parse_from(["ac", "session", "run", "--task", "run-task", "--sandbox"])
            .expect("parse run --sandbox");
        if let Commands::Session(SessionCmd::Run { sandbox, no_sandbox, .. }) = cli.command {
            assert!(sandbox);
            assert!(!no_sandbox);
        } else {
            panic!("expected SessionCmd::Run");
        }

        // --no-sandbox
        let cli = Cli::try_parse_from(["ac", "session", "run", "--task", "run-task", "--no-sandbox"])
            .expect("parse run --no-sandbox");
        if let Commands::Session(SessionCmd::Run { sandbox, no_sandbox, .. }) = cli.command {
            assert!(!sandbox);
            assert!(no_sandbox);
        } else {
            panic!("expected SessionCmd::Run");
        }

        // mutual exclusivity
        assert!(Cli::try_parse_from(["ac", "session", "run", "--task", "run-task", "--sandbox", "--no-sandbox"]).is_err());
    }
}
