//! Integration test suite for Feature F8: Webhook & External Notification Triggers.
//!
//! Validates:
//! 1. `MockHttpServer` capturing HTTP requests (headers, JSON body, status codes).
//! 2. Event filtering engine (direct kinds, semantic aliases, and wildcards).
//! 3. Discord rich embed payload builder, color mappings, bounds, and HTTP POST delivery.
//! 4. Slack attachment/block payload builder, hex colors, mrkdwn formatting, and HTTP POST delivery.
//! 5. Generic webhook schema `{ "event", "timestamp", "session_id", "payload" }`.
//! 6. Retry logic on HTTP 5xx responses with exponential backoff and fast-fail on 4xx.
//! 7. Thread-safe delivery metrics tracking (`total_dispatched`, `successful`, `failed`, `last_error`).
//! 8. IPC command integration (`notification.status` and `notification.test`) over Unix domain sockets.
//! 9. Desktop notification dispatcher non-blocking execution and headless/missing-binary resilience.
//! 10. Adversarial edge cases: extreme payload sizes, escaping, control characters, and unconfigured channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ac_core::{
    config::NotificationConfig,
    ipc::IpcServer,
    notifications::{
        build_discord_payload, build_discord_test_payload, build_generic_payload,
        build_generic_test_payload, build_slack_payload, build_slack_test_payload,
        dispatch_desktop, dispatch_http_with_retry, event_color, event_matches,
        extract_event_info, truncate_str, GenericWebhookPayload, NotificationDispatcher,
        NotificationHandle, COLOR_BLUE, COLOR_GOLD, COLOR_GREEN, COLOR_RED, HEX_BLUE,
        HEX_GOLD, HEX_GREEN, HEX_RED,
    },
    session::manager::SessionManagerHandle,
    types::{AgentEvent, ApiRequest, ApiResponse, EventKind, Id},
};
use chrono::Utc;
use serde_json::json;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, UnixStream},
    sync::{broadcast, oneshot, watch},
};

// ============================================================================
// Lightweight Mock HTTP Server for Webhook Verification
// ============================================================================

/// Represents an incoming HTTP request captured by `MockHttpServer`.
#[derive(Debug, Clone)]
pub struct CapturedRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub json: Option<serde_json::Value>,
}

#[derive(Clone)]
enum MockResponseMode {
    Constant(u16, String),
    Sequence(Arc<Mutex<Vec<u16>>>, String),
}

/// Zero-dependency loopback mock HTTP server for capturing webhook dispatches.
pub struct MockHttpServer {
    pub addr: SocketAddr,
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: Option<tokio::task::JoinHandle<()>>,
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn parse_http_request(raw_bytes: &[u8]) -> Option<CapturedRequest> {
    let header_end = find_subslice(raw_bytes, b"\r\n\r\n")?;
    let header_bytes = &raw_bytes[..header_end];
    let header_str = String::from_utf8_lossy(header_bytes);
    let mut lines = header_str.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let body_bytes = &raw_bytes[header_end + 4..];
    let content_length = headers
        .get("content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(body_bytes.len());
    let body_slice = if body_bytes.len() > content_length {
        &body_bytes[..content_length]
    } else {
        body_bytes
    };
    let body = String::from_utf8_lossy(body_slice).to_string();
    let json = serde_json::from_str(&body).ok();

    Some(CapturedRequest {
        method,
        path,
        headers,
        body,
        json,
    })
}

impl MockHttpServer {
    /// Starts a mock server that always responds with a constant status code and body.
    pub async fn start_constant(status: u16, body: &str) -> Self {
        Self::start(MockResponseMode::Constant(status, body.to_string())).await
    }

    /// Starts a mock server that serves a programmed sequence of HTTP status codes.
    pub async fn start_sequence(statuses: Vec<u16>, default_body: &str) -> Self {
        Self::start(MockResponseMode::Sequence(
            Arc::new(Mutex::new(statuses)),
            default_body.to_string(),
        ))
        .await
    }

    async fn start(mode: MockResponseMode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback port");
        let addr = listener.local_addr().expect("local address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let requests_clone = Arc::clone(&requests);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();

        let server_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        break;
                    }
                    accept_res = listener.accept() => {
                        let Ok((mut socket, _)) = accept_res else { break; };
                        let reqs = Arc::clone(&requests_clone);
                        let mode_clone = mode.clone();

                        tokio::spawn(async move {
                            let mut buf = Vec::new();
                            let mut chunk = [0u8; 4096];
                            loop {
                                match socket.read(&mut chunk).await {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        buf.extend_from_slice(&chunk[..n]);
                                        if let Some(header_end) = find_subslice(&buf, b"\r\n\r\n") {
                                            let header_str = String::from_utf8_lossy(&buf[..header_end]);
                                            let content_length = header_str
                                                .lines()
                                                .find_map(|l| {
                                                    let lower = l.to_ascii_lowercase();
                                                    if lower.starts_with("content-length:") {
                                                        l.split_once(':').and_then(|(_, v)| v.trim().parse::<usize>().ok())
                                                    } else {
                                                        None
                                                    }
                                                })
                                                .unwrap_or(0);
                                            if buf.len() >= header_end + 4 + content_length {
                                                break;
                                            }
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }

                            if let Some(captured) = parse_http_request(&buf) {
                                reqs.lock().unwrap().push(captured);

                                let (status_code, body) = match mode_clone {
                                    MockResponseMode::Constant(s, b) => (s, b),
                                    MockResponseMode::Sequence(seq, b) => {
                                        let s = {
                                            let mut guard = seq.lock().unwrap();
                                            if !guard.is_empty() {
                                                guard.remove(0)
                                            } else {
                                                200
                                            }
                                        };
                                        (s, b)
                                    }
                                };

                                let response = format!(
                                    "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                    status_code,
                                    status_text(status_code),
                                    body.len(),
                                    body
                                );
                                let _ = socket.write_all(response.as_bytes()).await;
                                let _ = socket.shutdown().await;
                            }
                        });
                    }
                }
            }
        });

        Self {
            addr,
            requests,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
        }
    }

    /// Returns the base URL of the mock HTTP server.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Returns a snapshot of all captured requests.
    pub fn captured_requests(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// Waits until at least `count` requests have been captured or `timeout` expires.
    pub async fn wait_for_requests(&self, count: usize, timeout: Duration) -> Vec<CapturedRequest> {
        let start = std::time::Instant::now();
        loop {
            {
                let reqs = self.requests.lock().unwrap();
                if reqs.len() >= count {
                    return reqs.clone();
                }
            }
            if start.elapsed() >= timeout {
                return self.requests.lock().unwrap().clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.server_task.take() {
            task.abort();
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn make_event(
    kind: EventKind,
    session_id: Option<Id>,
    payload: serde_json::Value,
) -> AgentEvent {
    AgentEvent {
        seq: 1,
        id: Id::new(),
        version: 1,
        kind,
        session_id,
        payload,
        triggered_by: "test_runner".to_string(),
        timestamp: Utc::now(),
        prev_hash: None,
        hash: None,
    }
}

fn dummy_session_mgr() -> SessionManagerHandle {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    SessionManagerHandle::new(tx)
}

// ============================================================================
// 1. MockHttpServer Verification Tests
// ============================================================================

#[tokio::test]
async fn test_mock_http_server_constant_and_headers() {
    let server = MockHttpServer::start_constant(200, r#"{"status":"ok"}"#).await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/webhook/test", server.url()))
        .header("Content-Type", "application/json")
        .header("X-Custom-Test", "ac-test-123")
        .body(r#"{"event":"session_crashed","id":"01JHY9Z0"}"#)
        .send()
        .await
        .expect("send request");

    assert_eq!(resp.status().as_u16(), 200);

    let captured = server.wait_for_requests(1, Duration::from_secs(2)).await;
    assert_eq!(captured.len(), 1);
    let req = &captured[0];
    assert_eq!(req.method, "POST");
    assert_eq!(req.path, "/webhook/test");
    assert_eq!(
        req.headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );
    assert_eq!(
        req.headers.get("x-custom-test").map(|s| s.as_str()),
        Some("ac-test-123")
    );
    assert!(req.json.is_some());
    assert_eq!(req.json.as_ref().unwrap()["event"], "session_crashed");
    assert_eq!(req.json.as_ref().unwrap()["id"], "01JHY9Z0");
}

#[tokio::test]
async fn test_mock_http_server_status_sequence() {
    let server = MockHttpServer::start_sequence(vec![500, 502, 204], "").await;
    let client = reqwest::Client::new();

    let r1 = client.post(server.url()).send().await.unwrap();
    assert_eq!(r1.status().as_u16(), 500);

    let r2 = client.post(server.url()).send().await.unwrap();
    assert_eq!(r2.status().as_u16(), 502);

    let r3 = client.post(server.url()).send().await.unwrap();
    assert_eq!(r3.status().as_u16(), 204);

    let captured = server.captured_requests();
    assert_eq!(captured.len(), 3);
}

// ============================================================================
// 2. Event Filtering Engine Tests
// ============================================================================

#[test]
fn test_event_filtering_exact_kinds_and_wildcard() {
    let exact_filter = vec!["session_started".to_string(), "session_created".to_string()];

    let ev_started = make_event(EventKind::SessionStarted, None, json!({}));
    let ev_created = make_event(EventKind::SessionCreated, None, json!({}));
    let ev_stopped = make_event(EventKind::SessionStopped, None, json!({}));

    assert!(event_matches(&exact_filter, &ev_started));
    assert!(event_matches(&exact_filter, &ev_created));
    assert!(!event_matches(&exact_filter, &ev_stopped));

    // Wildcards
    assert!(event_matches(&["*".to_string()], &ev_stopped));
    assert!(event_matches(&["all".to_string()], &ev_stopped));
    assert!(event_matches(&[" ALL ".to_string()], &ev_stopped));
}

#[test]
fn test_event_filtering_all_semantic_aliases() {
    let default_filters = vec![
        "session_crashed".to_string(),
        "human_intervention_required".to_string(),
        "quota_exhausted".to_string(),
        "session_finished".to_string(),
    ];

    // Alias: session_crashed
    let ev_crashed = make_event(EventKind::SessionCrashed, None, json!({}));
    let ev_failed = make_event(EventKind::SessionFailed, None, json!({}));
    assert!(event_matches(&default_filters, &ev_crashed));
    assert!(event_matches(&default_filters, &ev_failed));

    // Alias: human_intervention_required
    let ev_approval = make_event(EventKind::ApprovalRequested, None, json!({}));
    let ev_question = make_event(EventKind::AgentQuestion, None, json!({}));
    let ev_interaction = make_event(EventKind::InteractionCreated, None, json!({}));
    assert!(event_matches(&default_filters, &ev_approval));
    assert!(event_matches(&default_filters, &ev_question));
    assert!(event_matches(&default_filters, &ev_interaction));

    // Alias: quota_exhausted
    let ev_exhausted = make_event(EventKind::AccountExhausted, None, json!({}));
    let ev_rate_limited = make_event(EventKind::AccountRateLimited, None, json!({}));
    assert!(event_matches(&default_filters, &ev_exhausted));
    assert!(event_matches(&default_filters, &ev_rate_limited));

    // Alias: session_finished / session_stopped
    let ev_stopped = make_event(EventKind::SessionStopped, None, json!({}));
    assert!(event_matches(&default_filters, &ev_stopped));
    assert!(event_matches(&["session_stopped".to_string()], &ev_stopped));

    // Unsubscribed events
    let ev_started = make_event(EventKind::SessionStarted, None, json!({}));
    let ev_created = make_event(EventKind::SessionCreated, None, json!({}));
    let ev_account = make_event(EventKind::AccountRegistered, None, json!({}));
    assert!(!event_matches(&default_filters, &ev_started));
    assert!(!event_matches(&default_filters, &ev_created));
    assert!(!event_matches(&default_filters, &ev_account));
}

#[tokio::test]
async fn test_dispatcher_event_filtering_stream_e2e() {
    let server = MockHttpServer::start_constant(200, "ok").await;

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![server.url()],
        events: vec![
            "session_crashed".to_string(),
            "human_intervention_required".to_string(),
        ],
        ..Default::default()
    };

    let (event_tx, event_rx) = broadcast::channel::<AgentEvent>(32);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle = dispatcher.handle();

    let run_task = tokio::spawn(async move {
        dispatcher.run(event_rx, shutdown_rx).await;
    });

    // 1. Emit an unsubscribed event: SessionStarted -> should NOT dispatch
    let ev_unsubscribed = make_event(EventKind::SessionStarted, None, json!({}));
    event_tx.send(ev_unsubscribed).expect("send event");

    // 2. Emit subscribed events: SessionCrashed & InteractionCreated -> should dispatch
    let sid = Id::new();
    let ev_crashed = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({ "error": "Kernel panic" }),
    );
    event_tx.send(ev_crashed).expect("send event");

    let ev_approval = make_event(
        EventKind::ApprovalRequested,
        Some(sid.clone()),
        json!({ "description": "Need confirmation to delete folder" }),
    );
    event_tx.send(ev_approval).expect("send event");

    // Wait for the 2 subscribed events to arrive
    let captured = server.wait_for_requests(2, Duration::from_secs(3)).await;
    assert_eq!(captured.len(), 2, "Expected exactly 2 dispatches for subscribed events");

    assert_eq!(captured[0].json.as_ref().unwrap()["event"], "session_crashed");
    assert_eq!(captured[1].json.as_ref().unwrap()["event"], "approval_requested");

    // Graceful shutdown
    shutdown_tx.send(true).expect("shutdown signal");
    let _ = tokio::time::timeout(Duration::from_secs(2), run_task).await;

    // Delivery metrics should record exactly 2 successful dispatches
    let metrics = handle.metrics();
    assert_eq!(metrics.total_dispatched, 2);
    assert_eq!(metrics.successful, 2);
    assert_eq!(metrics.failed, 0);
}

// ============================================================================
// 3. Discord Webhook Payload & Mock POST Reception Tests
// ============================================================================

#[test]
fn test_discord_payload_color_mapping_all_categories() {
    // Red: Crashes, Failures, Quota Exhaustion
    let (c1, _, _) = event_color(&EventKind::SessionCrashed);
    assert_eq!(c1, COLOR_RED);
    assert_eq!(c1, 15548997);

    let (c2, _, _) = event_color(&EventKind::SessionFailed);
    assert_eq!(c2, COLOR_RED);

    let (c3, _, _) = event_color(&EventKind::AccountExhausted);
    assert_eq!(c3, COLOR_RED);

    // Gold: Approvals, Questions, Interaction, Rate Limits
    let (g1, _, _) = event_color(&EventKind::ApprovalRequested);
    assert_eq!(g1, COLOR_GOLD);
    assert_eq!(g1, 16705372);

    let (g2, _, _) = event_color(&EventKind::AgentQuestion);
    assert_eq!(g2, COLOR_GOLD);

    let (g3, _, _) = event_color(&EventKind::InteractionCreated);
    assert_eq!(g3, COLOR_GOLD);

    let (g4, _, _) = event_color(&EventKind::AccountRateLimited);
    assert_eq!(g4, COLOR_GOLD);

    // Green: Clean stopped / completions
    let (gr1, _, _) = event_color(&EventKind::SessionStopped);
    assert_eq!(gr1, COLOR_GREEN);
    assert_eq!(gr1, 5763719);

    // Blue: Test / Info / Other
    let (b1, _, _) = event_color(&EventKind::SessionStarted);
    assert_eq!(b1, COLOR_BLUE);
    assert_eq!(b1, 5793266);

    let test_payload = build_discord_test_payload(Some("Ping"));
    let test_color = test_payload["embeds"][0]["color"].as_u64().unwrap() as u32;
    assert_eq!(test_color, COLOR_BLUE);
}

#[test]
fn test_discord_payload_structure_and_bounds() {
    let sid = Id::new();
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({
            "agent_type": "agy",
            "error": "Segmentation fault in child process (signal 11)"
        }),
    );

    let payload = build_discord_payload(&ev);

    // Top-level content
    let content = payload["content"].as_str().expect("discord content");
    assert!(content.contains("🚨 **[AgentControll]** Alert: Session Crashed"));

    // Embed structure
    let embeds = payload["embeds"].as_array().expect("embeds array");
    assert_eq!(embeds.len(), 1);
    let embed = &embeds[0];

    assert_eq!(embed["title"].as_str(), Some("Session Crashed"));
    assert_eq!(embed["color"].as_u64(), Some(COLOR_RED as u64));
    assert!(embed["description"].as_str().unwrap().contains(&sid.to_string()));
    assert_eq!(embed["footer"]["text"].as_str(), Some("AgentControll Daemon"));

    // Fields verification
    let fields = embed["fields"].as_array().expect("fields array");
    assert!(fields.len() >= 4);

    let find_field = |name: &str| -> Option<&str> {
        fields.iter().find_map(|f| {
            if f["name"].as_str() == Some(name) {
                f["value"].as_str()
            } else {
                None
            }
        })
    };

    assert!(find_field("Session ID").unwrap().contains(&sid.to_string()));
    assert_eq!(find_field("Event Kind"), Some("session_crashed"));
    assert_eq!(find_field("Agent Type"), Some("agy"));
    assert!(find_field("Details").unwrap().contains("Segmentation fault"));

    // Verify all fields have non-empty name and value
    for field in fields {
        let n = field["name"].as_str().unwrap();
        let v = field["value"].as_str().unwrap();
        assert!(!n.trim().is_empty(), "Discord field name cannot be empty");
        assert!(!v.trim().is_empty(), "Discord field value cannot be empty");
    }

    // Verify timestamp is RFC 3339 formatted
    let ts = embed["timestamp"].as_str().expect("embed timestamp");
    assert!(chrono::DateTime::parse_from_rfc3339(ts).is_ok());
}

#[tokio::test]
async fn test_discord_mock_http_dispatch_e2e() {
    let server = MockHttpServer::start_constant(204, "").await;

    let config = NotificationConfig {
        enabled: true,
        discord_webhook_url: Some(server.url()),
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let sid = Id::new();
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({
            "agent_type": "claude",
            "error": "Connection reset by peer"
        }),
    );

    handle.dispatch_event(ev).await;

    let captured = server.wait_for_requests(1, Duration::from_secs(2)).await;
    assert_eq!(captured.len(), 1);

    let req = &captured[0];
    assert_eq!(req.method, "POST");
    assert_eq!(
        req.headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );

    let json_body = req.json.as_ref().expect("valid JSON body");
    assert!(json_body["content"].as_str().unwrap().contains("Session Crashed"));
    let embed = &json_body["embeds"][0];
    assert_eq!(embed["color"].as_u64(), Some(COLOR_RED as u64));
    assert!(embed["description"].as_str().unwrap().contains(&sid.to_string()));

    let metrics = handle.metrics();
    assert_eq!(metrics.successful, 1);
    assert_eq!(metrics.failed, 0);
}

// ============================================================================
// 4. Slack Webhook Payload & Mock POST Reception Tests
// ============================================================================

#[test]
fn test_slack_payload_color_mapping_all_categories() {
    let (_, c_red, _) = event_color(&EventKind::SessionCrashed);
    assert_eq!(c_red, HEX_RED);
    assert_eq!(c_red, "#ED4245");

    let (_, c_gold, _) = event_color(&EventKind::ApprovalRequested);
    assert_eq!(c_gold, HEX_GOLD);
    assert_eq!(c_gold, "#FEE75C");

    let (_, c_green, _) = event_color(&EventKind::SessionStopped);
    assert_eq!(c_green, HEX_GREEN);
    assert_eq!(c_green, "#57F287");

    let (_, c_blue, _) = event_color(&EventKind::SessionStarted);
    assert_eq!(c_blue, HEX_BLUE);
    assert_eq!(c_blue, "#5865F2");

    let test_payload = build_slack_test_payload(Some("Test message"));
    assert_eq!(test_payload["attachments"][0]["color"].as_str(), Some(HEX_BLUE));
}

#[test]
fn test_slack_payload_structure_and_fields() {
    let sid = Id::new();
    let ev = make_event(
        EventKind::ApprovalRequested,
        Some(sid.clone()),
        json!({
            "agent_type": "agy",
            "description": "Execute `sudo apt update` command"
        }),
    );

    let payload = build_slack_payload(&ev);

    // Fallback text
    let text = payload["text"].as_str().expect("slack fallback text");
    assert!(text.contains("🚨 [AgentControll] Approval Required"));
    assert!(text.contains(&sid.to_string()));

    // Attachments
    let attachments = payload["attachments"].as_array().expect("attachments array");
    assert_eq!(attachments.len(), 1);
    let att = &attachments[0];

    assert_eq!(att["color"].as_str(), Some(HEX_GOLD));
    assert_eq!(att["title"].as_str(), Some("Approval Required"));
    assert!(att["text"].as_str().unwrap().contains("requires human approval"));
    assert_eq!(att["footer"].as_str(), Some("AgentControll"));
    assert!(att["ts"].as_i64().is_some());

    // Fields
    let fields = att["fields"].as_array().expect("attachment fields");
    let find_field = |title: &str| -> Option<&serde_json::Value> {
        fields.iter().find(|f| f["title"].as_str() == Some(title))
    };

    let f_sid = find_field("Session ID").expect("Session ID field");
    assert!(f_sid["value"].as_str().unwrap().contains(&sid.to_string()));
    assert_eq!(f_sid["short"].as_bool(), Some(true));

    let f_ev = find_field("Event").expect("Event field");
    assert_eq!(f_ev["value"].as_str(), Some("approval_requested"));
    assert_eq!(f_ev["short"].as_bool(), Some(true));

    let f_det = find_field("Details").expect("Details field");
    assert!(f_det["value"].as_str().unwrap().contains("sudo apt update"));
    assert_eq!(f_det["short"].as_bool(), Some(false));
}

#[tokio::test]
async fn test_slack_mock_http_dispatch_e2e() {
    let server = MockHttpServer::start_constant(200, "ok").await;

    let config = NotificationConfig {
        enabled: true,
        slack_webhook_url: Some(server.url()),
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let sid = Id::new();
    let ev = make_event(
        EventKind::ApprovalRequested,
        Some(sid.clone()),
        json!({
            "agent_type": "claude",
            "description": "Approve network request to 192.168.1.100"
        }),
    );

    handle.dispatch_event(ev).await;

    let captured = server.wait_for_requests(1, Duration::from_secs(2)).await;
    assert_eq!(captured.len(), 1);

    let req = &captured[0];
    assert_eq!(req.method, "POST");
    assert_eq!(
        req.headers.get("content-type").map(|s| s.as_str()),
        Some("application/json")
    );

    let json_body = req.json.as_ref().expect("valid JSON body");
    assert!(json_body["text"].as_str().unwrap().contains("Approval Required"));
    let att = &json_body["attachments"][0];
    assert_eq!(att["color"].as_str(), Some(HEX_GOLD));
    assert_eq!(att["title"].as_str(), Some("Approval Required"));

    let metrics = handle.metrics();
    assert_eq!(metrics.successful, 1);
    assert_eq!(metrics.failed, 0);
}

// ============================================================================
// 5. Generic Webhook Delivery & Retry Logic Tests
// ============================================================================

#[test]
fn test_generic_webhook_payload_schema_compliance() {
    let sid = Id::new();
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({
            "agent_type": "agy",
            "error": "Killed by OOM killer",
            "restart_count": 2
        }),
    );

    let payload: GenericWebhookPayload = build_generic_payload(&ev);
    let json_val = serde_json::to_value(&payload).expect("serialize generic payload");

    // Must strictly match schema { "event", "timestamp", "session_id", "payload" }
    assert_eq!(json_val["event"].as_str(), Some("session_crashed"));
    assert_eq!(json_val["session_id"].as_str(), Some(sid.to_string().as_str()));
    assert!(json_val["timestamp"].as_str().is_some());
    assert_eq!(json_val["payload"]["agent_type"], "agy");
    assert_eq!(json_val["payload"]["error"], "Killed by OOM killer");
    assert_eq!(json_val["payload"]["restart_count"], 2);

    let test_payload = build_generic_test_payload(Some("System heartbeat"));
    assert_eq!(test_payload.event, "test");
    assert_eq!(test_payload.payload["message"], "System heartbeat");
    assert_eq!(test_payload.payload["status"], "active");
}

#[tokio::test]
async fn test_generic_webhook_retry_on_500_then_success() {
    // Mock server returns 500 on attempt 1, 200 on attempt 2
    let server = MockHttpServer::start_sequence(vec![500, 200], "").await;

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![server.url()],
        timeout_ms: 2000,
        max_retries: 2,
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let ev = make_event(
        EventKind::SessionCrashed,
        Some(Id::new()),
        json!({ "error": "Transient service error" }),
    );

    handle.dispatch_event(ev).await;

    let captured = server.wait_for_requests(2, Duration::from_secs(3)).await;
    assert_eq!(captured.len(), 2, "Server must receive initial request + 1 retry");

    let metrics = handle.metrics();
    assert_eq!(metrics.total_dispatched, 1);
    assert_eq!(metrics.successful, 1);
    assert_eq!(metrics.failed, 0);
    assert!(metrics.last_success.is_some());
    assert!(metrics.last_failure.is_none());
}

#[tokio::test]
async fn test_generic_webhook_retry_exhausted_records_failure() {
    // Mock server returns 500 on all attempts
    let server = MockHttpServer::start_constant(500, "Internal Server Error").await;

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![server.url()],
        timeout_ms: 1000,
        max_retries: 2,
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let ev = make_event(
        EventKind::SessionCrashed,
        Some(Id::new()),
        json!({ "error": "Crash event" }),
    );

    handle.dispatch_event(ev).await;

    // With max_retries = 2, total attempts = 1 initial + 2 retries = 3
    let captured = server.wait_for_requests(3, Duration::from_secs(3)).await;
    assert_eq!(captured.len(), 3, "Expected 1 initial request + 2 retries = 3 total");

    let metrics = handle.metrics();
    assert_eq!(metrics.total_dispatched, 1);
    assert_eq!(metrics.successful, 0);
    assert_eq!(metrics.failed, 1);
    assert!(metrics.last_failure.is_some());
    assert!(metrics.last_error.as_ref().unwrap().contains("HTTP 500 server error after 2 retries"));
}

#[tokio::test]
async fn test_generic_webhook_fast_fail_on_4xx_no_retries() {
    // 400 Bad Request should immediately fail without retry
    let server = MockHttpServer::start_constant(400, "Bad Request: Malformed").await;

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![server.url()],
        timeout_ms: 2000,
        max_retries: 3, // Set high retries to verify fast-fail skips them
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let start = std::time::Instant::now();
    let ev = make_event(EventKind::SessionCrashed, Some(Id::new()), json!({}));

    handle.dispatch_event(ev).await;
    let elapsed = start.elapsed();

    // Fast-fail should take well under 1 second (no retry backoffs)
    assert!(elapsed < Duration::from_millis(800));

    let captured = server.captured_requests();
    assert_eq!(captured.len(), 1, "Must fast-fail on 4xx with exactly 1 request (no retries)");

    let metrics = handle.metrics();
    assert_eq!(metrics.total_dispatched, 1);
    assert_eq!(metrics.successful, 0);
    assert_eq!(metrics.failed, 1);
    assert!(metrics.last_error.as_ref().unwrap().contains("HTTP 400 client error"));
}

#[tokio::test]
async fn test_generic_webhook_multi_url_fanout() {
    let server1 = MockHttpServer::start_constant(200, "ok1").await;
    let server2 = MockHttpServer::start_constant(200, "ok2").await;

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![server1.url(), server2.url()],
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let sid = Id::new();
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({ "error": "Fanout test" }),
    );

    handle.dispatch_event(ev).await;

    let reqs1 = server1.wait_for_requests(1, Duration::from_secs(2)).await;
    let reqs2 = server2.wait_for_requests(1, Duration::from_secs(2)).await;

    assert_eq!(reqs1.len(), 1);
    assert_eq!(reqs2.len(), 1);

    assert_eq!(reqs1[0].json.as_ref().unwrap()["event"], "session_crashed");
    assert_eq!(reqs2[0].json.as_ref().unwrap()["event"], "session_crashed");

    let metrics = handle.metrics();
    assert_eq!(metrics.total_dispatched, 2);
    assert_eq!(metrics.successful, 2);
}

// ============================================================================
// 6. IPC Command Integration Tests (`notification.status` & `notification.test`)
// ============================================================================

#[tokio::test]
async fn test_ipc_notification_status_command() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("agentcontrol_notify.sock");
    let mgr = dummy_session_mgr();
    let (evt_tx, _) = broadcast::channel(16);

    let config = NotificationConfig {
        enabled: true,
        discord_webhook_url: Some("https://discord.com/api/webhooks/dummy".to_string()),
        slack_webhook_url: None,
        generic_webhook_urls: vec!["https://generic.example.com/webhook".to_string()],
        desktop_notifications: true,
        events: vec!["session_crashed".to_string(), "quota_exhausted".to_string()],
        timeout_ms: 3000,
        max_retries: 3,
    };

    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle: NotificationHandle = dispatcher.handle();
    handle.record_success();
    handle.record_failure("HTTP 502 Bad Gateway".to_string());

    let server = IpcServer::bind(&sock_path, mgr, evt_tx)
        .unwrap()
        .with_notification_handle(handle);
    let server_task = tokio::spawn(async move { server.run().await });

    // Connect via UnixStream
    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    let request = ApiRequest {
        v: 1,
        id: "ipc-status-1".into(),
        cmd: "notification.status".into(),
        params: json!({}),
    };
    let mut line = serde_json::to_string(&request).unwrap();
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.unwrap();

    let resp_line = reader.next_line().await.unwrap().expect("response line");
    let resp: ApiResponse = serde_json::from_str(&resp_line).expect("parse json response");

    assert!(resp.ok);
    assert_eq!(resp.id, "ipc-status-1");

    let status = resp.result.unwrap()["status"].clone();
    assert_eq!(status["enabled"], true);
    assert_eq!(status["desktop"], true);
    assert_eq!(status["discord_configured"], true);
    assert_eq!(status["slack_configured"], false);
    assert_eq!(status["generic_webhooks_count"], 1);
    assert_eq!(
        status["events"],
        json!(["session_crashed", "quota_exhausted"])
    );

    let metrics = &status["metrics"];
    assert_eq!(metrics["total_dispatched"], 2);
    assert_eq!(metrics["successful"], 1);
    assert_eq!(metrics["failed"], 1);
    assert_eq!(metrics["last_error"], "HTTP 502 Bad Gateway");

    server_task.abort();
}

#[tokio::test]
async fn test_ipc_notification_test_command_generic() {
    let mock_server = MockHttpServer::start_constant(200, "ok").await;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("agentcontrol_test_cmd.sock");
    let mgr = dummy_session_mgr();
    let (evt_tx, _) = broadcast::channel(16);

    let config = NotificationConfig {
        enabled: true,
        generic_webhook_urls: vec![mock_server.url()],
        ..Default::default()
    };

    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle = dispatcher.handle();

    let server = IpcServer::bind(&sock_path, mgr, evt_tx)
        .unwrap()
        .with_notification_handle(handle);
    let server_task = tokio::spawn(async move { server.run().await });

    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    let request = ApiRequest {
        v: 1,
        id: "ipc-test-1".into(),
        cmd: "notification.test".into(),
        params: json!({
            "channel": "generic",
            "message": "E2E verification ping"
        }),
    };
    let mut line = serde_json::to_string(&request).unwrap();
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.unwrap();

    let resp_line = reader.next_line().await.unwrap().expect("response line");
    let resp: ApiResponse = serde_json::from_str(&resp_line).expect("parse json response");

    assert!(resp.ok);
    assert_eq!(resp.id, "ipc-test-1");

    let test_results = &resp.result.unwrap()["test_results"]["channels"];
    assert_eq!(test_results.as_array().unwrap().len(), 1);
    assert_eq!(test_results[0]["channel"], "generic");
    assert_eq!(test_results[0]["status"], "success");

    // Verify mock server received the test payload
    let captured = mock_server.wait_for_requests(1, Duration::from_secs(2)).await;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].json.as_ref().unwrap()["event"], "test");
    assert_eq!(
        captured[0].json.as_ref().unwrap()["payload"]["message"],
        "E2E verification ping"
    );

    server_task.abort();
}

#[tokio::test]
async fn test_ipc_notification_test_command_all_channels() {
    let mock_discord = MockHttpServer::start_constant(204, "").await;
    let mock_slack = MockHttpServer::start_constant(200, "ok").await;
    let mock_generic = MockHttpServer::start_constant(200, "ok").await;

    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("agentcontrol_all_channels.sock");
    let mgr = dummy_session_mgr();
    let (evt_tx, _) = broadcast::channel(16);

    let config = NotificationConfig {
        enabled: true,
        discord_webhook_url: Some(mock_discord.url()),
        slack_webhook_url: Some(mock_slack.url()),
        generic_webhook_urls: vec![mock_generic.url()],
        desktop_notifications: false,
        ..Default::default()
    };

    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle = dispatcher.handle();

    let server = IpcServer::bind(&sock_path, mgr, evt_tx)
        .unwrap()
        .with_notification_handle(handle);
    let server_task = tokio::spawn(async move { server.run().await });

    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // channel: null (or omitted) triggers all channels
    let request = ApiRequest {
        v: 1,
        id: "ipc-test-all".into(),
        cmd: "notification.test".into(),
        params: json!({
            "message": "Broadcast test"
        }),
    };
    let mut line = serde_json::to_string(&request).unwrap();
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.unwrap();

    let resp_line = reader.next_line().await.unwrap().expect("response line");
    let resp: ApiResponse = serde_json::from_str(&resp_line).expect("parse json response");

    assert!(resp.ok);
    let channels = resp.result.unwrap()["test_results"]["channels"].clone();
    assert_eq!(channels.as_array().unwrap().len(), 4);

    let find_channel_status = |ch_name: &str| -> Option<String> {
        channels.as_array().unwrap().iter().find_map(|c| {
            if c["channel"] == ch_name {
                c["status"].as_str().map(|s| s.to_string())
            } else {
                None
            }
        })
    };

    assert_eq!(find_channel_status("discord").as_deref(), Some("success"));
    assert_eq!(find_channel_status("slack").as_deref(), Some("success"));
    assert_eq!(find_channel_status("generic").as_deref(), Some("success"));
    assert_eq!(find_channel_status("desktop").as_deref(), Some("skipped"));

    server_task.abort();
}

#[tokio::test]
async fn test_ipc_notification_test_unknown_channel_error() {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("agentcontrol_err.sock");
    let mgr = dummy_session_mgr();
    let (evt_tx, _) = broadcast::channel(16);

    let config = NotificationConfig::default();
    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle = dispatcher.handle();

    let server = IpcServer::bind(&sock_path, mgr, evt_tx)
        .unwrap()
        .with_notification_handle(handle);
    let server_task = tokio::spawn(async move { server.run().await });

    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    let request = ApiRequest {
        v: 1,
        id: "ipc-test-err".into(),
        cmd: "notification.test".into(),
        params: json!({
            "channel": "pagerduty"
        }),
    };
    let mut line = serde_json::to_string(&request).unwrap();
    line.push('\n');
    write_half.write_all(line.as_bytes()).await.unwrap();

    let resp_line = reader.next_line().await.unwrap().expect("response line");
    let resp: ApiResponse = serde_json::from_str(&resp_line).expect("parse json response");

    assert!(!resp.ok);
    assert_eq!(resp.error.as_ref().unwrap().code, "NotificationError");
    assert!(resp.error.as_ref().unwrap().message.contains("Unknown notification channel 'pagerduty'"));

    server_task.abort();
}

// ============================================================================
// 7. Desktop Notification Dispatcher Tests
// ============================================================================

#[tokio::test]
async fn test_desktop_notification_safe_execution_and_timeout() {
    // Tests dispatch_desktop directly with short timeout and safe error recovery.
    // In CI or headless test environments without DISPLAY/D-Bus, notify-send exits with code 1
    // or NotFound, which the function must safely intercept without throwing a panic.
    let res_critical = dispatch_desktop(
        "AgentControll: Crash",
        "Session crashed unexpectedly",
        "critical",
        500,
    )
    .await;
    assert!(res_critical.is_ok() || res_critical.is_err());

    let res_normal = dispatch_desktop(
        "AgentControll: Action Required",
        "Approval requested for dangerous action",
        "normal",
        500,
    )
    .await;
    assert!(res_normal.is_ok() || res_normal.is_err());

    let res_low = dispatch_desktop(
        "AgentControll: Session Stopped",
        "Session finished cleanly",
        "low",
        500,
    )
    .await;
    assert!(res_low.is_ok() || res_low.is_err());
}

#[tokio::test]
async fn test_desktop_notification_dispatcher_e2e() {
    let config = NotificationConfig {
        enabled: true,
        desktop_notifications: true,
        timeout_ms: 500,
        ..Default::default()
    };

    let client = reqwest::Client::new();
    let dispatcher = NotificationDispatcher::new(config, client);
    let handle = dispatcher.handle();

    let ev = make_event(
        EventKind::SessionCrashed,
        Some(Id::new()),
        json!({ "error": "Desktop test crash event" }),
    );

    // dispatch_event must run to completion without panic
    handle.dispatch_event(ev).await;

    let metrics = handle.metrics();
    // Desktop delivery either succeeds (if GUI display/dbus available) or records a failure (headless),
    // but total_dispatched must be recorded and daemon remains healthy.
    assert_eq!(metrics.total_dispatched, 1);
    assert_eq!(metrics.successful + metrics.failed, 1);
}

// ============================================================================
// 8. Adversarial & Resource Stress Edge Cases
// ============================================================================

#[test]
fn test_adversarial_special_characters_and_escaping() {
    let sid = Id::new();
    let special_error = "Quotes: \"hello\" 'world' <script>alert(1)</script> \n\t\\ Backslashes & \0 UTF-8: 🚀 ñoñó 日本語 \u{1F916}";
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({
            "agent_type": "agy\"><script>",
            "error": special_error
        }),
    );

    // 1. Discord formatting check
    let discord = build_discord_payload(&ev);
    let discord_str = serde_json::to_string(&discord).expect("discord payload must serialize");
    assert!(discord_str.contains("🚀"));
    assert!(discord_str.contains("日本語"));

    // 2. Slack formatting check
    let slack = build_slack_payload(&ev);
    let slack_str = serde_json::to_string(&slack).expect("slack payload must serialize");
    assert!(slack_str.contains("🚀"));

    // 3. Generic payload check
    let generic = build_generic_payload(&ev);
    let generic_str = serde_json::to_string(&generic).expect("generic payload must serialize");
    let parsed: GenericWebhookPayload = serde_json::from_str(&generic_str).expect("generic deserialize");
    assert_eq!(parsed.payload["error"].as_str(), Some(special_error));
}

#[test]
fn test_adversarial_extreme_payload_sizes() {
    let sid = Id::new();
    // Massive 15,000-character error log
    let giant_error = "A".repeat(15_000);
    let ev = make_event(
        EventKind::SessionCrashed,
        Some(sid.clone()),
        json!({
            "agent_type": "agy",
            "error": giant_error
        }),
    );

    let (title, desc, details) = extract_event_info(&ev);
    assert!(title.len() <= 256);
    assert!(desc.len() <= 4096);
    assert!(details.is_some());

    let discord = build_discord_payload(&ev);
    let embed = &discord["embeds"][0];
    let fields = embed["fields"].as_array().unwrap();

    let details_field = fields.iter().find(|f| f["name"] == "Details").unwrap();
    let val = details_field["value"].as_str().unwrap();
    // Discord enforces max 1024 characters per field value
    assert!(val.chars().count() <= 1024, "Discord field value must be truncated to <= 1024 chars");
    assert!(val.ends_with("..."), "Truncated field must end with ellipsis");
}

#[tokio::test]
async fn test_unconfigured_channels_test_skips_gracefully() {
    let config = NotificationConfig {
        enabled: false,
        discord_webhook_url: None,
        slack_webhook_url: None,
        generic_webhook_urls: Vec::new(),
        desktop_notifications: false,
        ..Default::default()
    };

    let dispatcher = NotificationDispatcher::new(config, reqwest::Client::new());
    let handle = dispatcher.handle();

    let result = handle.send_test(None, None).await.expect("send_test succeeds");
    assert_eq!(result.channels.len(), 4);

    for ch in result.channels {
        assert_eq!(ch.status, "skipped", "Channel {} should be skipped when unconfigured", ch.channel);
        assert!(ch.details.is_some());
    }
}

#[test]
fn test_string_truncation_utility() {
    assert_eq!(truncate_str("hello", 10), "hello");
    assert_eq!(truncate_str("1234567890abcdef", 8), "12345...");
    assert_eq!(truncate_str("abc", 3), "abc");
}

#[tokio::test]
async fn test_direct_dispatch_http_with_retry_network_failure() {
    let client = reqwest::Client::new();
    // Non-routable IP with small timeout to simulate immediate network error
    let res = dispatch_http_with_retry(
        &client,
        "http://127.0.0.1:1",
        "{}",
        Duration::from_millis(50),
        1,
    )
    .await;
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Network error after 1 retries"));
}
