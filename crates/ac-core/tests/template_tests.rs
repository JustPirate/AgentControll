//! Integration tests for Reusable Session Templates & Presets (F10).
//!
//! Validates:
//! 1. Template CRUD via IPC protocol (`template.create`, `template.list`, `template.get`, `template.update`, `template.delete`)
//! 2. Resolution by ID and slug name (case-insensitive)
//! 3. Validation errors for invalid names, models, permission modes
//! 4. Conflict error for duplicate template names
//! 5. Dedicated session launch via `session.create_from_template` with default prompts, account tag matching, and overrides
//! 6. Token scope enforcement (mutating template commands rejected with `PermissionDenied` under `read` scope)
//! 7. End-to-end IPC communication over Unix domain socket

use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    event_store::EventStore,
    ipc::{dispatch_request_ext, IpcServer},
    session::manager::{SessionManager, SessionManagerHandle},
    template_manager::{TemplateManager, TemplateManagerHandle, TemplateStore},
    types::{Account, AgentEvent, ApiRequest, ApiResponse, TokenScope},
};
use serde_json::json;
use tempfile::tempdir;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
    sync::{broadcast, mpsc},
};

/// Set up a complete test harness with session manager, account manager, and template manager.
async fn setup_template_harness() -> (
    SessionManagerHandle,
    AccountManagerHandle,
    TemplateManagerHandle,
    broadcast::Sender<AgentEvent>,
    tempfile::TempDir,
) {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("events.db");
    let accts_db = dir.path().join("accounts.db");
    let templates_db = dir.path().join("templates.db");

    let store = EventStore::open(&db_path).unwrap();
    let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
    let (cmd_tx, cmd_rx) = mpsc::channel(64);

    // Setup accounts
    let acct_store = AccountStore::open(&accts_db).unwrap();
    let mut acct_mgr = AccountManager::new(acct_store).unwrap();
    let mock_acct = Account::new(
        "Tier1 Mock Account".into(),
        "mock".into(),
        vec!["agy".into(), "mock".into()],
        "ref:mock-1".into(),
        5,
        vec!["tier1".into(), "fast".into()],
    );
    acct_mgr.register(mock_acct).unwrap();
    let acct_handle = AccountManagerHandle::new(acct_mgr);

    let acct_store2 = AccountStore::open(&accts_db).unwrap();
    let acct_mgr2 = AccountManager::new(acct_store2).unwrap();

    // Setup templates
    let template_store = TemplateStore::open(&templates_db).unwrap();
    let template_mgr = TemplateManager::new(template_store).unwrap();
    let template_handle = TemplateManagerHandle::new(template_mgr);

    let adapter_factory = Box::new(ac_core::adapter::mock::MockAdapterFactory::always(
        ac_core::adapter::mock::default_script(),
    ));
    let mut manager = SessionManager::new(store, cmd_rx, event_tx.clone(), 3, adapter_factory)
        .with_account_manager(acct_mgr2);

    manager.recover_from_store().unwrap();
    let mgr_handle = SessionManagerHandle::new(cmd_tx);

    tokio::spawn(async move { manager.run().await });

    (mgr_handle, acct_handle, template_handle, event_tx, dir)
}

#[tokio::test]
async fn test_ipc_template_crud_lifecycle() {
    let (mgr, acct, tmpl, _tx, _dir) = setup_template_harness().await;

    // 1. Create a template
    let req_create = ApiRequest {
        v: 1,
        id: "create-1".into(),
        cmd: "template.create".into(),
        params: json!({
            "name": "code-review",
            "description": "Automated code reviewer",
            "agent_type": "agy",
            "default_task_prompt": "Perform a thorough review of all unstaged changes.",
            "account_tag": "tier1",
            "permission_mode": "normal",
            "model": "gemini-3.8-flash-medium",
            "launch": {
                "execution_mode": "plan",
                "sandbox": true
            }
        }),
    };

    let resp = dispatch_request_ext(
        &req_create,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;

    assert!(resp.ok, "template.create should succeed: {:?}", resp.error);
    let result = resp.result.expect("result must be present");
    let template_id = result["template_id"].as_str().unwrap().to_string();
    assert_eq!(result["name"], "code-review");

    // 2. Duplicate template creation rejected with Conflict
    let req_dup = ApiRequest {
        v: 1,
        id: "create-dup".into(),
        cmd: "template.create".into(),
        params: json!({
            "name": "code-review",
            "agent_type": "agy"
        }),
    };
    let resp_dup = dispatch_request_ext(
        &req_dup,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(!resp_dup.ok);
    assert_eq!(
        resp_dup.error.as_ref().unwrap().code,
        "Conflict",
        "Duplicate template must return Conflict"
    );

    // 3. Invalid name slug rejected with ValidationError
    let req_invalid = ApiRequest {
        v: 1,
        id: "create-invalid".into(),
        cmd: "template.create".into(),
        params: json!({
            "name": "invalid name with spaces",
            "agent_type": "agy"
        }),
    };
    let resp_invalid = dispatch_request_ext(
        &req_invalid,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(!resp_invalid.ok);
    assert_eq!(resp_invalid.error.as_ref().unwrap().code, "ValidationError");

    // 4. List templates
    let req_list = ApiRequest {
        v: 1,
        id: "list-1".into(),
        cmd: "template.list".into(),
        params: json!({}),
    };
    let resp_list = dispatch_request_ext(
        &req_list,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_list.ok);
    let templates = resp_list.result.unwrap()["templates"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(templates.len(), 1);
    assert_eq!(templates[0]["id"], template_id);
    assert_eq!(templates[0]["name"], "code-review");

    // 5. Get template by ID
    let req_get_id = ApiRequest {
        v: 1,
        id: "get-id".into(),
        cmd: "template.get".into(),
        params: json!({ "template": template_id }),
    };
    let resp_get_id = dispatch_request_ext(
        &req_get_id,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_get_id.ok);
    let got = &resp_get_id.result.unwrap()["template"];
    assert_eq!(got["name"], "code-review");
    assert_eq!(got["agent_type"], "agy");
    assert_eq!(
        got["default_task_prompt"],
        "Perform a thorough review of all unstaged changes."
    );

    // 6. Get template by slug name (case-insensitive)
    let req_get_name = ApiRequest {
        v: 1,
        id: "get-name".into(),
        cmd: "template.get".into(),
        params: json!({ "name": "CODE-REVIEW" }),
    };
    let resp_get_name = dispatch_request_ext(
        &req_get_name,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_get_name.ok);
    assert_eq!(resp_get_name.result.unwrap()["template"]["id"], template_id);

    // 7. Update template description
    let req_update = ApiRequest {
        v: 1,
        id: "update-1".into(),
        cmd: "template.update".into(),
        params: json!({
            "template": "code-review",
            "description": "Updated review preset"
        }),
    };
    let resp_update = dispatch_request_ext(
        &req_update,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_update.ok);

    let resp_get_updated = dispatch_request_ext(
        &req_get_id,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert_eq!(
        resp_get_updated.result.unwrap()["template"]["description"],
        "Updated review preset"
    );

    // 8. Delete template
    let req_delete = ApiRequest {
        v: 1,
        id: "delete-1".into(),
        cmd: "template.delete".into(),
        params: json!({ "template": "code-review" }),
    };
    let resp_delete = dispatch_request_ext(
        &req_delete,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_delete.ok);

    // Verify template is gone
    let resp_get_deleted = dispatch_request_ext(
        &req_get_id,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(!resp_get_deleted.ok);
    assert_eq!(
        resp_get_deleted.error.as_ref().unwrap().code,
        "NotFound"
    );
}

#[tokio::test]
async fn test_ipc_session_create_from_template() {
    let (mgr, acct, tmpl, _tx, _dir) = setup_template_harness().await;

    // 1. Create a template with launch options, prompt, and account tag
    let req_create = ApiRequest {
        v: 1,
        id: "create-t".into(),
        cmd: "template.create".into(),
        params: json!({
            "name": "backend-task",
            "agent_type": "agy",
            "default_task_prompt": "Run cargo test and fix bugs",
            "account_tag": "tier1",
            "model": "gemini-3.8-flash-medium",
            "permission_mode": "normal",
            "launch": {
                "execution_mode": "plan",
                "sandbox": true
            }
        }),
    };
    let resp_create = dispatch_request_ext(
        &req_create,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_create.ok);
    let template_id = resp_create.result.unwrap()["template_id"]
        .as_str()
        .unwrap()
        .to_string();

    // 2. Launch session from template using default prompt and start = false
    let req_launch = ApiRequest {
        v: 1,
        id: "launch-1".into(),
        cmd: "session.create_from_template".into(),
        params: json!({
            "template": "backend-task",
            "start": false
        }),
    };
    let resp_launch = dispatch_request_ext(
        &req_launch,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_launch.ok, "Launch should succeed: {:?}", resp_launch.error);
    let launch_res = resp_launch.result.unwrap();
    let session_id = launch_res["session_id"].as_str().unwrap().to_string();
    assert_eq!(launch_res["template_id"], template_id);

    // Verify session state and populated configuration
    let req_get_sess = ApiRequest {
        v: 1,
        id: "get-sess".into(),
        cmd: "session.get".into(),
        params: json!({ "session_id": session_id }),
    };
    let resp_sess = dispatch_request_ext(
        &req_get_sess,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_sess.ok);
    let session = resp_sess.result.unwrap();
    assert_eq!(session["task_description"], "Run cargo test and fix bugs");
    assert_eq!(session["agent_type"], "agy");
    assert!(session["account_id"].is_string(), "Account should be auto-assigned via tag");
    assert_eq!(session["launch"]["execution_mode"], "plan");
    assert_eq!(session["launch"]["sandbox"], true);
    assert_eq!(session["launch"]["model"], "gemini-3.8-flash-medium");

    // 3. Launch with caller prompt override and start = true
    let req_launch_override = ApiRequest {
        v: 1,
        id: "launch-2".into(),
        cmd: "session.create_from_template".into(),
        params: json!({
            "template": template_id,
            "task_description": "Overridden task description for urgent review",
            "start": true
        }),
    };
    let resp_override = dispatch_request_ext(
        &req_launch_override,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_override.ok, "Override should succeed: {:?}", resp_override.error);
    let s2_id = resp_override.result.unwrap()["session_id"]
        .as_str()
        .unwrap()
        .to_string();

    let req_get_s2 = ApiRequest {
        v: 1,
        id: "get-s2".into(),
        cmd: "session.get".into(),
        params: json!({ "session_id": s2_id }),
    };
    let resp_s2 = dispatch_request_ext(
        &req_get_s2,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(resp_s2.ok);
    assert_eq!(
        resp_s2.result.unwrap()["task_description"],
        "Overridden task description for urgent review"
    );

    // 4. Missing template returns NotFound
    let req_missing = ApiRequest {
        v: 1,
        id: "launch-missing".into(),
        cmd: "session.create_from_template".into(),
        params: json!({ "template": "nonexistent-template-slug" }),
    };
    let resp_missing = dispatch_request_ext(
        &req_missing,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Admin),
    )
    .await;
    assert!(!resp_missing.ok);
    assert_eq!(resp_missing.error.as_ref().unwrap().code, "NotFound");
}

#[tokio::test]
async fn test_ipc_token_scope_enforcement_on_template_commands() {
    let (mgr, acct, tmpl, _tx, _dir) = setup_template_harness().await;

    // Mutating template command under read scope must fail with PermissionDenied
    let req_mutating = ApiRequest {
        v: 1,
        id: "read-deny-1".into(),
        cmd: "template.create".into(),
        params: json!({ "name": "forbidden-template", "agent_type": "agy" }),
    };
    let resp = dispatch_request_ext(
        &req_mutating,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Read),
    )
    .await;
    assert!(!resp.ok);
    assert_eq!(resp.error.as_ref().unwrap().code, "PermissionDenied");

    let req_launch_read = ApiRequest {
        v: 1,
        id: "read-deny-2".into(),
        cmd: "session.create_from_template".into(),
        params: json!({ "template": "forbidden-template" }),
    };
    let resp_launch = dispatch_request_ext(
        &req_launch_read,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Read),
    )
    .await;
    assert!(!resp_launch.ok);
    assert_eq!(resp_launch.error.as_ref().unwrap().code, "PermissionDenied");

    // Read-only template commands must succeed under read scope
    let req_list = ApiRequest {
        v: 1,
        id: "read-allow".into(),
        cmd: "template.list".into(),
        params: json!({}),
    };
    let resp_list = dispatch_request_ext(
        &req_list,
        &mgr,
        &Some(acct.clone()),
        &None,
        &None,
        &None,
        &Some(tmpl.clone()),
        Some(TokenScope::Read),
    )
    .await;
    assert!(resp_list.ok, "template.list should be allowed for read scope");
}

#[tokio::test]
async fn test_ipc_socket_template_roundtrip() {
    let (mgr, acct, tmpl, event_tx, dir) = setup_template_harness().await;
    let sock_path = dir.path().join("test_template.sock");

    let server = IpcServer::bind(&sock_path, mgr.clone(), event_tx)
        .unwrap()
        .with_account_manager(acct)
        .with_template_manager(tmpl);

    tokio::spawn(async move { server.run().await });

    // Connect via Unix domain socket
    let stream = UnixStream::connect(&sock_path).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half).lines();

    // Send template.create
    let req1 = json!({
        "v": 1,
        "id": "wire-1",
        "cmd": "template.create",
        "params": {
            "name": "socket-test-template",
            "agent_type": "agy",
            "default_task_prompt": "Socket test prompt",
            "model": "gemini-3.8-flash-medium"
        }
    });
    write_half
        .write_all(format!("{req1}\n").as_bytes())
        .await
        .unwrap();

    let line1 = reader.next_line().await.unwrap().unwrap();
    let resp1: ApiResponse = serde_json::from_str(&line1).unwrap();
    assert!(resp1.ok);
    let tmpl_id = resp1.result.unwrap()["template_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Send session.create_from_template
    let req2 = json!({
        "v": 1,
        "id": "wire-2",
        "cmd": "session.create_from_template",
        "params": {
            "template": "socket-test-template",
            "start": false
        }
    });
    write_half
        .write_all(format!("{req2}\n").as_bytes())
        .await
        .unwrap();

    let line2 = reader.next_line().await.unwrap().unwrap();
    let resp2: ApiResponse = serde_json::from_str(&line2).unwrap();
    assert!(resp2.ok);
    let res2 = resp2.result.unwrap();
    assert!(res2["session_id"].is_string());
    assert_eq!(res2["template_id"], tmpl_id);
}
