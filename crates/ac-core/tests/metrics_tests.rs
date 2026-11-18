//! Comprehensive integration test suite for Feature F12: Native Metrics & OpenTelemetry Export.
//!
//! Validates:
//! 1. HTTP server endpoints (`GET /metrics`, `GET /health`, `GET /livez`, 404 on unknown, 405 on POST)
//! 2. IPC `metrics.get` round-trip returning Prometheus text and structured JSON
//! 3. Correct counter and gauge increments across session creation, crash, restart, and interaction approval
//! 4. Prometheus 0.0.4 text format compliance, header declarations, and label escaping

use std::collections::HashMap;
use std::net::SocketAddr;

use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    event_store::EventStore,
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::{dispatch_request_ext, IpcServer},
    metrics::{HttpServer, MetricsCollector},
    policy_engine::{PolicyEngine, PolicyStore},
    session::manager::{SessionManager, SessionManagerHandle},
    types::{
        Account, AgentEvent, ApiRequest, ApiResponse, EventKind,
        PolicyDecision,
    },
};
use serde_json::json;
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, UnixStream},
    sync::{broadcast, mpsc},
};

/// Helper to parse simple HTTP/1.1 response string into (status_code, headers, body).
fn parse_http_response(raw: &str) -> (u16, HashMap<String, String>, String) {
    let (head, body) = if let Some(pos) = raw.find("\r\n\r\n") {
        (&raw[..pos], raw[pos + 4..].to_string())
    } else if let Some(pos) = raw.find("\n\n") {
        (&raw[..pos], raw[pos + 2..].to_string())
    } else {
        (raw, String::new())
    };

    let mut lines = head.lines();
    let status_line = lines.next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }

    (status_code, headers, body)
}

async fn http_get(addr: SocketAddr, path: &str) -> (u16, HashMap<String, String>, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        path, addr
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp).to_string();
    parse_http_response(&text)
}

async fn http_post(
    addr: SocketAddr,
    path: &str,
    body: &str,
) -> (u16, HashMap<String, String>, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path,
        addr,
        body.len(),
        body
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    stream.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp).to_string();
    parse_http_response(&text)
}

/// Helper to wait for a specific agent event with timeout.
async fn wait_for_event<F>(rx: &mut broadcast::Receiver<AgentEvent>, predicate: F) -> AgentEvent
where
    F: Fn(&AgentEvent) -> bool,
{
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let event = rx.recv().await.expect("event_rx closed");
            if predicate(&event) {
                return event;
            }
        }
    })
    .await
    .expect("timed out waiting for event")
}

/// Harness setting up all core subsystems for metrics testing.
struct MetricsTestHarness {
    session_mgr: SessionManagerHandle,
    account_mgr: AccountManagerHandle,
    interaction_hub: InteractionHubHandle,
    event_tx: broadcast::Sender<AgentEvent>,
    _dir: tempfile::TempDir,
}

impl MetricsTestHarness {
    async fn new() -> Self {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("events.db");
        let accts_db = dir.path().join("accounts.db");

        let store = EventStore::open(&db_path).unwrap();
        let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
        let (cmd_tx, cmd_rx) = mpsc::channel(64);

        // Accounts
        let acct_store = AccountStore::open(&accts_db).unwrap();
        let acct_mgr = AccountManager::new(acct_store).unwrap();
        let account_mgr = AccountManagerHandle::new(acct_mgr);

        // Interaction Hub
        let policy_store = PolicyStore::open_in_memory().unwrap();
        let policy_engine = PolicyEngine::new(policy_store).unwrap();
        let interaction_store = InteractionStore::open_in_memory().unwrap();
        let hub = InteractionHub::new(interaction_store, policy_engine).unwrap();
        let interaction_hub = InteractionHubHandle::new(hub);

        // Adapter factory with mock adapter
        let adapter_factory = Box::new(ac_core::adapter::mock::MockAdapterFactory::always(
            ac_core::adapter::mock::default_script(),
        ));

        let mut manager = SessionManager::new(store, cmd_rx, event_tx.clone(), 3, adapter_factory)
            .with_account_manager_handle(account_mgr.clone())
            .with_interaction_hub(interaction_hub.clone());

        manager.recover_from_store().unwrap();
        let session_mgr = SessionManagerHandle::new(cmd_tx);

        tokio::spawn(async move { manager.run().await });

        Self {
            session_mgr,
            account_mgr,
            interaction_hub,
            event_tx,
            _dir: dir,
        }
    }

    fn collector(&self) -> MetricsCollector {
        MetricsCollector::new(
            self.session_mgr.clone(),
            Some(self.account_mgr.clone()),
            Some(self.interaction_hub.clone()),
        )
        .with_event_channel(&self.event_tx)
    }
}

#[tokio::test]
async fn test_http_metrics_and_health_endpoints() {
    let harness = MetricsTestHarness::new().await;
    let collector = harness.collector();

    // Bind to ephemeral port 0 to prevent conflicts
    let server = HttpServer::bind("127.0.0.1:0", collector).await.unwrap();
    let addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move { server.run().await });

    // 1. Test GET /health
    let (status, headers, body) = http_get(addr, "/health").await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );
    let health: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(health["status"], "ok");
    assert_eq!(health["version"], env!("CARGO_PKG_VERSION"));

    // 2. Test GET /livez
    let (status, headers, body) = http_get(addr, "/livez").await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );
    let livez: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(livez["status"], "ok");

    // 3. Test GET /metrics
    let (status, headers, body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200);
    assert_eq!(
        headers.get("content-type").map(|s| s.as_str()),
        Some("text/plain; version=0.0.4; charset=utf-8")
    );
    assert!(body.contains("# HELP agentcontrol_sessions_total"));
    assert!(body.contains("# TYPE agentcontrol_sessions_total counter"));
    assert!(body.contains("agentcontrol_sessions_total 0"));
    assert!(body.contains("# HELP agentcontrol_sessions_active"));
    assert!(body.contains("agentcontrol_sessions_active{state=\"idle\"} 0"));
    assert!(body.contains("agentcontrol_sessions_active{state=\"working\"} 0"));
    assert!(body.contains("# HELP agentcontrol_session_crashes_total"));
    assert!(body.contains("agentcontrol_session_crashes_total 0"));
    assert!(body.contains("# HELP agentcontrol_session_restarts_total"));
    assert!(body.contains("agentcontrol_session_restarts_total 0"));
    assert!(body.contains("# HELP agentcontrol_session_duration_seconds"));
    assert!(body.contains("agentcontrol_session_duration_seconds_bucket{le=\"+Inf\"} 0"));
    assert!(body.contains("# HELP agentcontrol_interactions_total"));
    assert!(body.contains("agentcontrol_interactions_total{decision=\"allow\"} 0"));
    assert!(body.contains("# HELP agentcontrol_interactions_pending"));
    assert!(body.contains("agentcontrol_interactions_pending 0"));
    assert!(body.contains("# HELP agentcontrol_interaction_approval_latency_seconds"));
    assert!(body.contains("# HELP agentcontrol_accounts_total"));
    assert!(body.contains("# HELP agentcontrol_events_total"));

    // 4. Test 404 on unknown endpoint
    let (status, _, body) = http_get(addr, "/unknown_path").await;
    assert_eq!(status, 404);
    assert_eq!(body, "Not Found");

    // 5. Test 405 on POST method
    let (status, _, body) = http_post(addr, "/metrics", "payload").await;
    assert_eq!(status, 405);
    assert_eq!(body, "Method Not Allowed");

    server_task.abort();
}

#[tokio::test]
async fn test_ipc_metrics_get_roundtrip() {
    let harness = MetricsTestHarness::new().await;

    let req = ApiRequest {
        v: 1,
        id: "req-metrics-1".into(),
        cmd: "metrics.get".into(),
        params: json!({}),
    };

    let resp = dispatch_request_ext(
        &req,
        &harness.session_mgr,
        &Some(harness.account_mgr.clone()),
        &None,
        &Some(harness.interaction_hub.clone()),
        &None,
        &None,
        None,
    )
    .await;

    assert!(resp.ok);
    assert_eq!(resp.id, "req-metrics-1");
    let result = resp.result.unwrap();

    // Verify Prometheus text representation
    let prom = result["prometheus"].as_str().unwrap();
    assert!(prom.contains("agentcontrol_sessions_total 0"));
    assert!(prom.contains("agentcontrol_sessions_active{state=\"idle\"} 0"));
    assert!(prom.contains("agentcontrol_session_crashes_total 0"));

    // Verify structured JSON representation
    let metrics = &result["metrics"];
    assert_eq!(metrics["sessions"]["total"], 0);
    assert_eq!(metrics["sessions"]["crashes_total"], 0);
    assert_eq!(metrics["sessions"]["restarts_total"], 0);
    assert_eq!(metrics["interactions"]["pending"], 0);
    assert_eq!(metrics["interactions"]["total_by_decision"]["allow"], 0);
    assert_eq!(metrics["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn test_ipc_server_socket_metrics_command() {
    let harness = MetricsTestHarness::new().await;
    let socket_path = harness._dir.path().join("test_agentcontrol.sock");

    let server = IpcServer::bind(
        &socket_path,
        harness.session_mgr.clone(),
        harness.event_tx.clone(),
    )
    .unwrap()
    .with_account_manager(harness.account_mgr.clone())
    .with_interaction_hub(harness.interaction_hub.clone());

    let server_task = tokio::spawn(async move { server.run().await });

    // Connect via UnixStream
    let stream = UnixStream::connect(&socket_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    let request = json!({
        "v": 1,
        "id": "sock-m1",
        "cmd": "metrics.get",
        "params": {}
    });
    let mut line = request.to_string();
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.unwrap();

    let resp_line = reader.next_line().await.unwrap().unwrap();
    let resp: ApiResponse = serde_json::from_str(&resp_line).unwrap();

    assert!(resp.ok);
    assert_eq!(resp.id, "sock-m1");
    let result = resp.result.unwrap();
    assert!(result["prometheus"].is_string());
    assert!(result["metrics"].is_object());

    server_task.abort();
}

#[tokio::test]
async fn test_counter_and_gauge_increments_on_events() {
    let harness = MetricsTestHarness::new().await;
    let collector = harness.collector();

    // Baseline check
    let snap0 = collector.gather().await.unwrap();
    assert_eq!(snap0.sessions_total, 0);
    assert_eq!(snap0.session_crashes_total, 0);
    assert_eq!(snap0.session_restarts_total, 0);

    // 1. Register an account supporting the mock agent adapter
    let acct = Account::new(
        "Prod Account".into(),
        "anthropic".into(),
        vec!["mock".into(), "claude".into()],
        "cred:123".into(),
        4,
        vec!["prod".into()],
    );
    harness.account_mgr.0.lock().unwrap().register(acct).unwrap();

    let snap_acct = collector.gather().await.unwrap();
    assert_eq!(snap_acct.accounts_total_by_provider.get("anthropic"), Some(&1));
    assert_eq!(snap_acct.account_concurrency_caps.len(), 1);
    assert_eq!(snap_acct.account_concurrency_caps[0].provider, "anthropic");
    assert_eq!(snap_acct.account_concurrency_caps[0].concurrency_cap, 4);

    // 2. Create a session (binds to the registered account)
    let sid = harness
        .session_mgr
        .create("Test metrics task".into(), "mock".into())
        .await
        .unwrap();

    let snap1 = collector.gather().await.unwrap();
    assert_eq!(snap1.sessions_total, 1);
    assert_eq!(snap1.sessions_active_by_state.get("idle"), Some(&1));
    assert_eq!(snap1.account_concurrency_caps[0].active_sessions, 1);

    // 3. Start session
    harness.session_mgr.start(sid.clone()).await.unwrap();

    let snap2 = collector.gather().await.unwrap();
    assert_eq!(snap2.sessions_total, 1);
    // Working state should now be 1
    assert_eq!(snap2.sessions_active_by_state.get("working"), Some(&1));
    assert_eq!(snap2.session_duration_seconds.count, 1);

    // 4. Test Interaction submission and approval
    let submission = harness
        .interaction_hub
        .0
        .lock()
        .unwrap()
        .submit_approval_request(
            sid.clone(),
            "shell_execute".into(),
            Some(json!({ "cmd": "cargo test" })),
            "Execute test suite?".into(),
            Some("mock"),
            None,
        )
        .unwrap();

    let interaction_id = match submission {
        ac_core::interaction_hub::InteractionSubmissionResult::Escalated { interaction } => {
            interaction.id
        }
        _ => panic!("Expected escalated interaction requiring approval"),
    };

    let snap4 = collector.gather().await.unwrap();
    assert_eq!(snap4.interactions_pending, 1);

    // Approve interaction
    harness
        .interaction_hub
        .0
        .lock()
        .unwrap()
        .reply(
            &interaction_id,
            Some(PolicyDecision::Allow),
            Some("Approved by QA".into()),
            Some("tester".into()),
        )
        .unwrap();

    let snap5 = collector.gather().await.unwrap();
    assert_eq!(snap5.interactions_pending, 0);
    assert_eq!(
        snap5.interactions_total_by_decision.get("allow"),
        Some(&1)
    );
    assert_eq!(snap5.approval_latency_seconds.count, 1);

    // 5. Test crash event and restart increment
    // Emit a crash event through event bus
    let crash_event = AgentEvent::new(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({ "exit_code": 137, "reason": "SIGKILL" }),
        "adapter",
    );
    let _ = harness.event_tx.send(crash_event);

    // Give broadcast subscriber a tick to process
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let snap6 = collector.gather().await.unwrap();
    assert_eq!(snap6.session_crashes_total, 1);

    // Emit a restart event
    let restart_event = AgentEvent::new(
        EventKind::SessionRestartAttempted,
        Some(sid.clone()),
        json!({ "attempt": 1 }),
        "system",
    );
    let _ = harness.event_tx.send(restart_event);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let snap7 = collector.gather().await.unwrap();
    assert_eq!(snap7.session_restarts_total, 1);

    // Emitting SessionRestartSucceeded must NOT increment session_restarts_total again
    let restart_succ = AgentEvent::new(
        EventKind::SessionRestartSucceeded,
        Some(sid.clone()),
        json!({}),
        "adapter:mock",
    );
    let _ = harness.event_tx.send(restart_succ);
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let snap8 = collector.gather().await.unwrap();
    assert_eq!(snap8.session_restarts_total, 1);
}

#[tokio::test]
async fn test_prometheus_escaping_and_formatting() {
    let harness = MetricsTestHarness::new().await;
    let collector = harness.collector();

    // Register account with special characters: quotes, backslash, newlines
    let special_acct = Account::new(
        "label \"with\" quotes\\and\nnewlines".into(),
        "provider\\custom\"test".into(),
        vec!["mock".into()],
        "cred:esc".into(),
        2,
        vec![],
    );
    harness
        .account_mgr
        .0
        .lock()
        .unwrap()
        .register(special_acct)
        .unwrap();

    let snap = collector.gather().await.unwrap();
    let prom = MetricsCollector::format_prometheus(&snap);

    // Verify backslash, quotes and newline escaping in label values
    assert!(prom.contains("provider=\"provider\\\\custom\\\"test\""));
    assert!(prom.contains("label=\"label \\\"with\\\" quotes\\\\and\\nnewlines\""));

    // Verify format contains HELP and TYPE for all required metric families
    assert!(prom.contains("# HELP agentcontrol_sessions_total"));
    assert!(prom.contains("# TYPE agentcontrol_sessions_total counter"));
    assert!(prom.contains("# HELP agentcontrol_sessions_active"));
    assert!(prom.contains("# TYPE agentcontrol_sessions_active gauge"));
    assert!(prom.contains("# HELP agentcontrol_session_crashes_total"));
    assert!(prom.contains("# TYPE agentcontrol_session_crashes_total counter"));
    assert!(prom.contains("# HELP agentcontrol_session_restarts_total"));
    assert!(prom.contains("# TYPE agentcontrol_session_restarts_total counter"));
    assert!(prom.contains("# HELP agentcontrol_session_duration_seconds"));
    assert!(prom.contains("# TYPE agentcontrol_session_duration_seconds histogram"));
    assert!(prom.contains("# HELP agentcontrol_interactions_total"));
    assert!(prom.contains("# TYPE agentcontrol_interactions_total counter"));
    assert!(prom.contains("# HELP agentcontrol_interactions_pending"));
    assert!(prom.contains("# TYPE agentcontrol_interactions_pending gauge"));
    assert!(prom.contains("# HELP agentcontrol_interaction_approval_latency_seconds"));
    assert!(prom.contains("# TYPE agentcontrol_interaction_approval_latency_seconds histogram"));
    assert!(prom.contains("# HELP agentcontrol_accounts_total"));
    assert!(prom.contains("# TYPE agentcontrol_accounts_total gauge"));
    assert!(prom.contains("# HELP agentcontrol_account_concurrency_cap"));
    assert!(prom.contains("# TYPE agentcontrol_account_concurrency_cap gauge"));
    assert!(prom.contains("# HELP agentcontrol_account_active_sessions"));
    assert!(prom.contains("# TYPE agentcontrol_account_active_sessions gauge"));
    assert!(prom.contains("# HELP agentcontrol_events_total"));
    assert!(prom.contains("# TYPE agentcontrol_events_total counter"));
}

#[tokio::test]
async fn test_session_restart_telemetry_consistency_http_and_ipc() {
    let harness = MetricsTestHarness::new().await;
    let mut rx = harness.event_tx.subscribe();

    // 1. Register an account for the mock adapter
    let acct = Account::new(
        "Restart Account".into(),
        "anthropic".into(),
        vec!["mock".into()],
        "cred:restart".into(),
        2,
        vec!["prod".into()],
    );
    harness.account_mgr.0.lock().unwrap().register(acct).unwrap();

    // 2. Start HTTP metrics server with live collector
    let server = HttpServer::bind("127.0.0.1:0", harness.collector())
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let server_task = tokio::spawn(async move { server.run().await });

    // 3. Create and start a session
    let sid = harness
        .session_mgr
        .create("Restart test session".into(), "mock".into())
        .await
        .unwrap();
    harness.session_mgr.start(sid.clone()).await.unwrap();

    // Wait until session is working
    wait_for_event(&mut rx, |e| {
        e.kind == EventKind::StateChanged
            && e.session_id == Some(sid.clone())
            && e.payload["to"].as_str() == Some("working")
    })
    .await;

    // 4. Stop session
    harness
        .session_mgr
        .stop(sid.clone(), Some("Stopping before restart".into()))
        .await
        .unwrap();

    wait_for_event(&mut rx, |e| {
        e.kind == EventKind::StateChanged
            && e.session_id == Some(sid.clone())
            && e.payload["to"].as_str() == Some("stopped")
    })
    .await;

    // 5. Verify baseline restarts = 0 on both HTTP and IPC
    let (status, _, http_baseline) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200);
    assert!(http_baseline.contains("agentcontrol_session_restarts_total 0"));

    let req_baseline = ApiRequest {
        v: 1,
        id: "req-baseline".into(),
        cmd: "metrics.get".into(),
        params: json!({}),
    };
    let resp_baseline = dispatch_request_ext(
        &req_baseline,
        &harness.session_mgr,
        &Some(harness.account_mgr.clone()),
        &None,
        &Some(harness.interaction_hub.clone()),
        &None,
        &None,
        None,
    )
    .await;
    assert_eq!(
        resp_baseline.result.unwrap()["metrics"]["sessions"]["restarts_total"],
        0
    );

    // 6. Resume stopped session (triggers session restart)
    harness.session_mgr.resume(sid.clone()).await.unwrap();

    // SessionManager emits SessionRestartAttempted, then SessionRestartSucceeded
    wait_for_event(&mut rx, |e| {
        e.kind == EventKind::SessionRestartAttempted && e.session_id == Some(sid.clone())
    })
    .await;

    wait_for_event(&mut rx, |e| {
        e.kind == EventKind::SessionRestartSucceeded && e.session_id == Some(sid.clone())
    })
    .await;

    // Brief yield to ensure the background event bus listener processed the events
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // 7. Scrape HTTP /metrics: verify restart count is exactly 1 (NOT 2)
    let (status, _, http_body) = http_get(addr, "/metrics").await;
    assert_eq!(status, 200);
    assert!(
        http_body.contains("agentcontrol_session_restarts_total 1"),
        "HTTP exporter must report exactly 1 restart, got: {}",
        http_body
    );
    assert!(
        !http_body.contains("agentcontrol_session_restarts_total 2"),
        "HTTP exporter must NOT report 2 restarts (double-counted attempt + succeeded)"
    );

    let http_restarts_line = http_body
        .lines()
        .find(|l| l.starts_with("agentcontrol_session_restarts_total "))
        .expect("agentcontrol_session_restarts_total line found");
    let http_restarts: u64 = http_restarts_line
        .split_whitespace()
        .nth(1)
        .expect("metric value")
        .parse()
        .expect("valid u64");
    assert_eq!(http_restarts, 1);

    // 8. Query IPC metrics.get: verify restart count is exactly 1
    let req_ipc = ApiRequest {
        v: 1,
        id: "req-ipc-restart".into(),
        cmd: "metrics.get".into(),
        params: json!({}),
    };
    let resp_ipc = dispatch_request_ext(
        &req_ipc,
        &harness.session_mgr,
        &Some(harness.account_mgr.clone()),
        &None,
        &Some(harness.interaction_hub.clone()),
        &None,
        &None,
        None,
    )
    .await;
    assert!(resp_ipc.ok);
    let ipc_res = resp_ipc.result.unwrap();
    let ipc_restarts = ipc_res["metrics"]["sessions"]["restarts_total"]
        .as_u64()
        .expect("u64 restarts_total");
    assert_eq!(
        ipc_restarts, 1,
        "IPC exporter must report exactly 1 restart"
    );
    let ipc_prom = ipc_res["prometheus"].as_str().unwrap();
    assert!(
        ipc_prom.contains("agentcontrol_session_restarts_total 1"),
        "IPC prometheus text must report 1 restart"
    );

    // 9. Verify HTTP and IPC return the exact same value
    assert_eq!(
        http_restarts, ipc_restarts,
        "HTTP scraping ({}) and IPC query ({}) must return the exact same value for session restarts",
        http_restarts, ipc_restarts
    );

    server_task.abort();
}
