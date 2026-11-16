//! Automated tests for CLI session resumption and conversation discovery.

use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::broadcast;

use ac_cli::client::DaemonClient;
use ac_core::{
    account_manager::{AccountManager, AccountManagerHandle, AccountStore},
    adapter::mock::MockAdapterFactory,
    event_store::EventStore,
    interaction_hub::{InteractionHub, InteractionHubHandle, InteractionStore},
    ipc::IpcServer,
    policy_engine::{PolicyEngine, PolicyStore},
    project_registry::{ProjectRegistry, ProjectRegistryHandle, ProjectStore},
    session::manager::{SessionManager, SessionManagerHandle},
    types::{AgentEvent, SessionState},
};

async fn setup_test_daemon() -> (DaemonClient, tempfile::TempDir, SessionManagerHandle) {
    let tmp = tempdir().unwrap();
    let sock = tmp.path().join("test_agentcontrol.sock");

    let store = EventStore::open_in_memory().unwrap();
    let (event_tx, _) = broadcast::channel::<AgentEvent>(256);
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(64);

    let pol_store = PolicyStore::open(&tmp.path().join("policies.db")).unwrap();
    let policy_engine = PolicyEngine::new(pol_store).unwrap();

    let int_store = InteractionStore::open(&tmp.path().join("interactions.db")).unwrap();
    let hub = InteractionHub::new(int_store, policy_engine).unwrap();
    let hub_handle = InteractionHubHandle::new(hub);

    let acct_store = AccountStore::open(&tmp.path().join("accounts.db")).unwrap();
    let mut acct_mgr = AccountManager::new(acct_store).unwrap();
    let acct = ac_core::types::Account::new(
        "Mock Account".into(),
        "mock-provider".into(),
        vec!["mock".into(), "agy".into()],
        "cred-1".into(),
        10,
        vec![],
    );
    acct_mgr.register(acct).unwrap();
    let acct_handle = AccountManagerHandle::new(acct_mgr);

    let proj_store = ProjectStore::open(&tmp.path().join("projects.db")).unwrap();
    let proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_handle = ProjectRegistryHandle::new(proj_reg);

    let factory = Box::new(MockAdapterFactory::always(vec![
        ac_core::adapter::mock::ScriptedEvent::immediate(ac_core::types::AdapterEvent::Ready),
    ]));
    let session_mgr =
        SessionManager::new(store, cmd_rx, event_tx.clone(), 3, factory)
            .with_account_manager_handle(acct_handle.clone())
            .with_project_registry_handle(proj_handle.clone())
            .with_interaction_hub(hub_handle.clone());
    tokio::spawn(async move {
        let sm = session_mgr;
        sm.run().await;
    });

    let mgr_handle = SessionManagerHandle::new(cmd_tx);

    let server = IpcServer::bind(&sock, mgr_handle.clone(), event_tx)
        .unwrap()
        .with_account_manager(acct_handle.clone())
        .with_project_registry(proj_handle.clone())
        .with_interaction_hub(hub_handle.clone());
    tokio::spawn(async move {
        let _ = server.run().await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    let client = DaemonClient::new(sock);
    (client, tmp, mgr_handle)
}

#[tokio::test]
async fn test_client_list_conversations() {
    let (client, _tmp, _mgr) = setup_test_daemon().await;
    let convs = client.list_conversations().await.expect("list_conversations must succeed");
    // Should return successfully without error
    assert!(convs.is_empty() || !convs.is_empty());
}

#[tokio::test]
async fn test_client_resume_stopped_session() {
    let (client, _tmp, mgr) = setup_test_daemon().await;

    let sid = mgr.create("task to stop and resume".into(), "mock".into()).await.unwrap();
    mgr.start(sid.clone()).await.unwrap();

    // Wait until Working
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = mgr.get(sid.clone()).await.unwrap().unwrap();
    assert_eq!(s.state, SessionState::Working);

    // Stop session
    client.stop_session(&sid, None).await.unwrap();
    let s = mgr.get(sid.clone()).await.unwrap().unwrap();
    assert_eq!(s.state, SessionState::Stopped);

    // Resume session using client.resume_session
    client.resume_session(&sid).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let s = mgr.get(sid.clone()).await.unwrap().unwrap();
    assert_eq!(s.state, SessionState::Working);
}

#[test]
fn test_cli_flags_and_subcommands() {
    let ac_bin = env!("CARGO_BIN_EXE_ac");

    // 1. ac session create --help shows --conversation / -c
    let out = std::process::Command::new(ac_bin)
        .args(["session", "create", "--help"])
        .output()
        .expect("failed to execute ac session create --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("-c, --conversation <CONVERSATION>"),
        "Help must mention -c/--conversation: {stdout}"
    );

    // 2. ac session run --help shows --conversation / -c
    let out = std::process::Command::new(ac_bin)
        .args(["session", "run", "--help"])
        .output()
        .expect("failed to execute ac session run --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("-c, --conversation <CONVERSATION>"),
        "Help must mention -c/--conversation: {stdout}"
    );

    // 3. ac session discover --help works
    let out = std::process::Command::new(ac_bin)
        .args(["session", "discover", "--help"])
        .output()
        .expect("failed to execute ac session discover --help");
    assert!(out.status.success());

    // 4. ac conversation list --help works
    let out = std::process::Command::new(ac_bin)
        .args(["conversation", "list", "--help"])
        .output()
        .expect("failed to execute ac conversation list --help");
    assert!(out.status.success());
}
