//! Autonomous Quota Failover and 429 Auto-Handoff Integration Tests.
//!
//! Validates:
//! 1. Active session encountering 429/RateLimitSignal -> Account enters Cooldown/Exhausted ->
//!    automatic hand-off to lowest active load backup account of the same provider ->
//!    successor session starts in same workspace with snapshot intact -> AccountSwitchCompleted emitted.
//! 2. Dynamic configuration toggle: `enabled = false` does not hand off, transitions session to RateLimited.
//! 3. Graceful fallback when no backup accounts are available -> transitions to RateLimited, emits SessionHandOffFailed.
//! 4. Provider matching isolation: never fails over to a different provider.
//! 5. Canonical provider matching: "agy" matches "antigravity", "claude" matches "anthropic".
//! 6. Account cooldown automatic expirationsweeper: restores expired accounts to Active rotation.
//! 7. PTY regex pattern matching for agy/antigravity quota and 429 messages.
//! 8. Context snapshot enhancement: successor receives full prompt/snapshot context.
//! 9. Child exit/crash suppression for sessions already in HandedOff or Stopping state.

use std::time::Duration;
use tokio::sync::{broadcast, mpsc};

use ac_core::{
    account_manager::{AccountManager, AccountStore},
    adapter::mock::{MockAdapterFactory, MockScript, ScriptedEvent},
    adapter::pty::{PtyPatternKind, PtyPatternRule},
    config::Config,
    event_store::EventStore,
    project_registry::{ProjectRegistry, ProjectStore},
    session::manager::{canonical_provider, providers_match, SessionManager, SessionManagerHandle},
    types::{
        Account, AccountState, AccountSwitchMode, AdapterEvent, AgentEvent, Confidence, EventKind,
        Id, Project, ProviderCapabilities, SessionState, WorkspacePolicy,
    },
};
use chrono::Utc;

// ── Test Harness Helpers ──────────────────────────────────────────────────────

fn make_account(label: &str, provider: &str, agent_types: Vec<&str>, cap: u8) -> Account {
    Account::new(
        label.into(),
        provider.into(),
        agent_types.into_iter().map(String::from).collect(),
        format!("ref:{label}"),
        cap,
        vec!["test".into()],
    )
}

fn make_project(name: &str, ws_path: &str) -> Project {
    Project::new(
        name.into(),
        ws_path.into(),
        Some("mock".into()),
        vec![],
        WorkspacePolicy::Shared,
    )
}

fn create_test_session_manager(
    scripts: Vec<MockScript>,
    account_mgr: AccountManager,
    project_reg: ProjectRegistry,
    auto_failover: bool,
) -> (SessionManagerHandle, broadcast::Receiver<AgentEvent>) {
    let factory = MockAdapterFactory::sequence(scripts).with_capabilities(
        ProviderCapabilities::new(AccountSwitchMode::RequiresRestart, true, true),
    );

    let event_store = EventStore::open_in_memory().unwrap();
    let (cmd_tx, cmd_rx) = mpsc::channel(128);
    let (event_tx, event_rx) = broadcast::channel(512);

    let manager = SessionManager::new(event_store, cmd_rx, event_tx, 3, Box::new(factory))
        .with_account_manager(account_mgr)
        .with_project_registry(project_reg)
        .with_auto_failover(auto_failover);

    tokio::spawn(async move { manager.run().await });
    (SessionManagerHandle::new(cmd_tx), event_rx)
}

// ── Test 1: Timed Rate Limit -> Cooldown -> Lowest-Load Auto Handoff ─────────

#[tokio::test]
async fn test_auto_failover_timed_rate_limit_to_lowest_load_backup() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    // Account A: initial active account (concurrency_cap: 1)
    let id_a = acct_mgr
        .register(make_account("acct-a", "anthropic", vec!["mock"], 1))
        .unwrap();

    // Account B: backup account (concurrency_cap: 3)
    let id_b = acct_mgr
        .register(make_account("acct-b", "anthropic", vec!["mock"], 3))
        .unwrap();

    // Account C: backup account (concurrency_cap: 3)
    let id_c = acct_mgr
        .register(make_account("acct-c", "anthropic", vec!["mock"], 3))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-failover", "/tmp/ac_test_ws_failover_1"))
        .unwrap();

    // Script 1: Initial session receives Ready, then RateLimitSignal with 60s cooldown
    let script_pred = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal {
                back_off_secs: Some(60),
            },
        ),
    ];

    // Script 2: Successor session starts and runs steadily
    let script_succ = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            10_000,
            AdapterEvent::OutputChunk {
                text: "Successor session working smoothly".into(),
                confidence: Confidence::High,
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script_pred, script_succ],
        acct_mgr,
        proj_reg,
        true, // auto_failover enabled
    );

    // Pre-allocate a session to Account B so that Account B has active load = 1
    let _sid_busy = mgr
        .create_with_context(
            "Existing busy session on Account B".into(),
            "mock".into(),
            None,
            Some(id_b.clone()),
        )
        .await
        .unwrap();

    // Create and start initial session on Account A (which will failover to Account C)
    let sid1 = mgr
        .create_with_context(
            "Long running task encountering 429".into(),
            "mock".into(),
            Some(proj_id.clone()),
            Some(id_a.clone()),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    // Await failover events
    let mut account_rate_limited = false;
    let mut cooldown_started = false;
    let mut handoff_completed = false;
    let mut switch_completed = false;
    let mut successor_id: Option<Id> = None;

    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    match evt.kind {
                        EventKind::AccountRateLimited => {
                            account_rate_limited = true;
                        }
                        EventKind::AccountCooldownStarted => {
                            cooldown_started = true;
                        }
                        EventKind::SessionHandOffCompleted => {
                            handoff_completed = true;
                            if let Some(succ) = evt.payload.get("successor_session_id").and_then(|v| v.as_str()) {
                                successor_id = Some(Id::from(succ));
                            }
                        }
                        EventKind::AccountSwitchCompleted => {
                            switch_completed = true;
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    assert!(account_rate_limited, "AccountRateLimited must be emitted");
    assert!(cooldown_started, "AccountCooldownStarted must be emitted");
    assert!(handoff_completed, "SessionHandOffCompleted must be emitted");
    assert!(switch_completed, "AccountSwitchCompleted must be emitted");

    let sid2 = successor_id.expect("Successor session ID must be captured from handoff event");
    assert_ne!(sid1, sid2, "Successor must have a new distinct session ID");

    // Predecessor state assertions
    let predecessor = mgr.get(sid1.clone()).await.unwrap().unwrap();
    assert_eq!(predecessor.state, SessionState::HandedOff);
    assert_eq!(predecessor.successor_id, Some(sid2.clone()));
    assert!(predecessor.context_snapshot_id.is_some());

    // Successor state assertions
    let successor = mgr.get(sid2.clone()).await.unwrap().unwrap();
    assert_eq!(successor.state, SessionState::Working);
    assert_eq!(successor.predecessor_id, Some(sid1.clone()));
    assert_eq!(
        successor.account_id,
        Some(id_c.clone()),
        "Must select Account C because it had load=0, whereas Account B had load=1"
    );
    assert_eq!(successor.project_id, Some(proj_id));
    assert_eq!(successor.workspace_id, predecessor.workspace_id);
    assert_eq!(successor.task_description, predecessor.task_description);

    // Verify predecessor event audit trail
    let pred_events = mgr.query_events(Some(sid1.clone()), None).await.unwrap();
    let kinds: Vec<EventKind> = pred_events.iter().map(|e| e.kind.clone()).collect();
    assert!(kinds.contains(&EventKind::AccountRateLimited));
    assert!(kinds.contains(&EventKind::AccountCooldownStarted));
    assert!(kinds.contains(&EventKind::SessionSnapshotCreated));
    assert!(kinds.contains(&EventKind::SessionHandOffStarted));
    assert!(kinds.contains(&EventKind::SessionHandOffCompleted));
    assert!(kinds.contains(&EventKind::AccountSwitchCompleted));
}

// ── Test 2: Quota Exhaustion -> Exhausted State -> Failover ───────────────────

#[tokio::test]
async fn test_auto_failover_quota_exhaustion_marks_exhausted() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    let id_a = acct_mgr
        .register(make_account("acct-a", "anthropic", vec!["mock"], 1))
        .unwrap();
    let id_b = acct_mgr
        .register(make_account("acct-b", "anthropic", vec!["mock"], 2))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-exh", "/tmp/ac_test_ws_exh"))
        .unwrap();

    // Script 1: RateLimitSignal with back_off_secs: None signals permanent quota exhaustion
    let script_pred = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal { back_off_secs: None },
        ),
    ];
    let script_succ = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            10_000,
            AdapterEvent::OutputChunk {
                text: "Successor active".into(),
                confidence: Confidence::High,
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script_pred, script_succ],
        acct_mgr,
        proj_reg,
        true,
    );

    let sid1 = mgr
        .create_with_context(
            "Task with zero remaining quota".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_a.clone()),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let mut account_exhausted = false;
    let mut switch_completed = false;

    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    if evt.kind == EventKind::AccountExhausted {
                        account_exhausted = true;
                    }
                    if evt.kind == EventKind::AccountSwitchCompleted {
                        switch_completed = true;
                        break;
                    }
                }
            }
        }
    }

    assert!(account_exhausted, "AccountExhausted must be emitted");
    assert!(switch_completed, "AccountSwitchCompleted must be emitted");

    let predecessor = mgr.get(sid1.clone()).await.unwrap().unwrap();
    assert_eq!(predecessor.state, SessionState::HandedOff);

    let succ_id = predecessor.successor_id.unwrap();
    let successor = mgr.get(succ_id).await.unwrap().unwrap();
    assert_eq!(successor.state, SessionState::Working);
    assert_eq!(successor.account_id, Some(id_b));
}

// ── Test 3: Crashed with 429/Quota Reason Triggers Failover ──────────────────

#[tokio::test]
async fn test_auto_failover_crashed_with_429_reason_triggers_failover() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    let id_a = acct_mgr
        .register(make_account("acct-a", "anthropic", vec!["mock"], 1))
        .unwrap();
    let id_b = acct_mgr
        .register(make_account("acct-b", "anthropic", vec!["mock"], 1))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-crash429", "/tmp/ac_test_ws_crash429"))
        .unwrap();

    // Adapter child crashes immediately due to HTTP 429
    let script_pred = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::Crashed {
                exit_code: Some(1),
                reason: Some("HTTP 429 Too Many Requests: Rate limit exceeded".into()),
            },
        ),
    ];
    let script_succ = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            10_000,
            AdapterEvent::OutputChunk {
                text: "Successor recovered from crash".into(),
                confidence: Confidence::High,
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script_pred, script_succ],
        acct_mgr,
        proj_reg,
        true,
    );

    let sid1 = mgr
        .create_with_context(
            "Task that crashes on 429".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_a.clone()),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let mut switch_completed = false;
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    if evt.kind == EventKind::AccountSwitchCompleted {
                        switch_completed = true;
                        break;
                    }
                }
            }
        }
    }

    assert!(switch_completed, "AccountSwitchCompleted must be emitted after crash failover");
    let predecessor = mgr.get(sid1).await.unwrap().unwrap();
    assert_eq!(predecessor.state, SessionState::HandedOff);

    let successor = mgr.get(predecessor.successor_id.unwrap()).await.unwrap().unwrap();
    assert_eq!(successor.state, SessionState::Working);
    assert_eq!(successor.account_id, Some(id_b));
}

// ── Test 4: Dynamic Config Toggle: enabled = false Does Not Hand Off ─────────

#[tokio::test]
async fn test_auto_failover_disabled_in_config_transitions_to_rate_limited() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    let id_a = acct_mgr
        .register(make_account("acct-a", "anthropic", vec!["mock"], 1))
        .unwrap();
    let _id_b = acct_mgr
        .register(make_account("acct-b", "anthropic", vec!["mock"], 1))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-disabled", "/tmp/ac_test_ws_disabled"))
        .unwrap();

    let script = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal {
                back_off_secs: Some(60),
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script],
        acct_mgr,
        proj_reg,
        false, // auto_failover disabled
    );

    let sid1 = mgr
        .create_with_context(
            "Task with auto-failover disabled".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_a),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let mut rate_limited_emitted = false;
    let timeout = tokio::time::sleep(Duration::from_millis(500));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    if evt.kind == EventKind::AccountRateLimited {
                        rate_limited_emitted = true;
                    }
                    if evt.kind == EventKind::SessionHandOffStarted
                        || evt.kind == EventKind::AccountSwitchCompleted
                    {
                        panic!("Hand-off must NOT start when auto_failover is disabled");
                    }
                }
            }
        }
    }

    assert!(rate_limited_emitted);
    let session = mgr.get(sid1).await.unwrap().unwrap();
    assert_eq!(session.state, SessionState::RateLimited);
    assert!(session.successor_id.is_none());
}

// ── Test 5: Graceful Fallback When No Backup Account is Available ─────────────

#[tokio::test]
async fn test_auto_failover_graceful_fallback_when_no_backup_available() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    // Only one account exists in the pool
    let id_a = acct_mgr
        .register(make_account("lone-acct", "anthropic", vec!["mock"], 1))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-lone", "/tmp/ac_test_ws_lone"))
        .unwrap();

    let script = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal {
                back_off_secs: Some(60),
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script],
        acct_mgr,
        proj_reg,
        true, // auto-failover enabled, but no backup exists
    );

    let sid1 = mgr
        .create_with_context(
            "Task with no backup accounts available".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_a),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let mut handoff_failed = false;
    let mut switch_failed = false;

    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    if evt.kind == EventKind::SessionHandOffFailed {
                        handoff_failed = true;
                    }
                    if evt.kind == EventKind::AccountSwitchFailed {
                        switch_failed = true;
                    }
                }
            }
        }
    }

    assert!(handoff_failed, "SessionHandOffFailed must be emitted");
    assert!(switch_failed, "AccountSwitchFailed must be emitted");

    let session = mgr.get(sid1).await.unwrap().unwrap();
    assert_eq!(
        session.state,
        SessionState::RateLimited,
        "Session must transition to RateLimited when no backup accounts exist"
    );
    assert!(session.successor_id.is_none());
}

// ── Test 6: Provider Matching Isolation ──────────────────────────────────────

#[tokio::test]
async fn test_auto_failover_provider_matching_isolation() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    // Anthropic account encounters rate limit
    let id_anthropic = acct_mgr
        .register(make_account("acct-anthropic", "anthropic", vec!["mock"], 1))
        .unwrap();

    // Google account available, supporting "mock" agent_type
    let id_google = acct_mgr
        .register(make_account("acct-google", "google", vec!["mock"], 1))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-prov", "/tmp/ac_test_ws_prov"))
        .unwrap();

    let script = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal {
                back_off_secs: Some(60),
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script],
        acct_mgr,
        proj_reg,
        true,
    );

    let sid1 = mgr
        .create_with_context(
            "Anthropic session".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_anthropic.clone()),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let mut handoff_failed = false;
    let timeout = tokio::time::sleep(Duration::from_secs(3));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                if let Ok(evt) = res {
                    if evt.kind == EventKind::SessionHandOffFailed {
                        handoff_failed = true;
                    }
                    if evt.kind == EventKind::AccountSwitchCompleted {
                        panic!("Failover must NEVER switch to a different provider!");
                    }
                }
            }
        }
    }

    assert!(handoff_failed, "Handoff must fail because no Anthropic backup account exists");
    let session = mgr.get(sid1).await.unwrap().unwrap();
    assert_eq!(session.state, SessionState::RateLimited);
    assert_ne!(session.account_id, Some(id_google));
}

// ── Test 7: Canonical Provider Aliases ────────────────────────────────────────

#[test]
fn test_canonical_provider_aliases() {
    assert_eq!(canonical_provider("agy"), "agy");
    assert_eq!(canonical_provider("antigravity"), "agy");
    assert_eq!(canonical_provider("AGY"), "agy");
    assert_eq!(canonical_provider("Antigravity"), "agy");

    assert_eq!(canonical_provider("claude"), "claude");
    assert_eq!(canonical_provider("claude-code"), "claude");
    assert_eq!(canonical_provider("anthropic"), "claude");
    assert_eq!(canonical_provider("Claude"), "claude");

    assert!(providers_match("agy", "antigravity"));
    assert!(providers_match("antigravity", "agy"));
    assert!(providers_match("claude", "anthropic"));
    assert!(providers_match("claude-code", "claude"));
    assert!(providers_match("custom-provider", "custom-provider"));

    assert!(!providers_match("agy", "claude"));
    assert!(!providers_match("anthropic", "google"));
    assert!(!providers_match("openai", "anthropic"));
}

// ── Test 8: Cooldown Sweeping and Expiration ──────────────────────────────────

#[test]
fn test_cooldown_expiration_sweeps_accounts_to_active() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    let id1 = acct_mgr
        .register(make_account("acct-1", "agy", vec!["agy"], 1))
        .unwrap();
    let id2 = acct_mgr
        .register(make_account("acct-2", "agy", vec!["agy"], 1))
        .unwrap();
    let id3 = acct_mgr
        .register(make_account("acct-3", "agy", vec!["agy"], 1))
        .unwrap();
    let id4 = acct_mgr
        .register(make_account("acct-4", "agy", vec!["agy"], 1))
        .unwrap();

    let past = Utc::now() - chrono::Duration::seconds(30);
    let future = Utc::now() + chrono::Duration::seconds(3600);

    // Account 1: Cooldown with past timestamp -> should expire to Active
    acct_mgr.start_cooldown(&id1, past).unwrap();
    // Account 2: RateLimited with past timestamp -> should expire to Active
    acct_mgr.apply_rate_limit(&id2, Some(past)).unwrap();
    // Account 3: Cooldown with future timestamp -> should remain in Cooldown
    acct_mgr.start_cooldown(&id3, future).unwrap();
    // Account 4: Exhausted -> should remain Exhausted
    acct_mgr.mark_exhausted(&id4).unwrap();

    assert_eq!(acct_mgr.get(&id1).unwrap().state, AccountState::Cooldown);
    assert_eq!(acct_mgr.get(&id2).unwrap().state, AccountState::RateLimited);
    assert_eq!(acct_mgr.get(&id3).unwrap().state, AccountState::Cooldown);
    assert_eq!(acct_mgr.get(&id4).unwrap().state, AccountState::Exhausted);

    let expired = acct_mgr.maybe_expire_all_cooldowns().unwrap();
    assert_eq!(expired.len(), 2);
    assert!(expired.contains(&id1));
    assert!(expired.contains(&id2));
    assert!(!expired.contains(&id3));
    assert!(!expired.contains(&id4));

    assert_eq!(acct_mgr.get(&id1).unwrap().state, AccountState::Active);
    assert_eq!(acct_mgr.get(&id1).unwrap().cooldown_until, None);
    assert_eq!(acct_mgr.get(&id2).unwrap().state, AccountState::Active);
    assert_eq!(acct_mgr.get(&id2).unwrap().cooldown_until, None);
    assert_eq!(acct_mgr.get(&id3).unwrap().state, AccountState::Cooldown);
    assert_eq!(acct_mgr.get(&id4).unwrap().state, AccountState::Exhausted);
}

// ── Test 9: PTY Pattern Matching for agy/antigravity Quota Messages ──────────

#[test]
fn test_pty_pattern_matching_agy_quota_messages() {
    let quota_pattern = r"(?i)(rate limit|429|quota exhausted|resource has been exhausted|rate_limit_exceeded|quota exceeded)";
    let rule = PtyPatternRule::new(
        quota_pattern,
        PtyPatternKind::RateLimitSignal {
            back_off_secs: Some(60),
        },
    )
    .expect("PTY pattern compilation");

    // Positive matches
    assert!(rule.pattern.is_match("Error: 429 Too Many Requests"));
    assert!(rule.pattern.is_match("HTTP 429: rate limit exceeded"));
    assert!(rule.pattern.is_match("Google Cloud: resource has been exhausted"));
    assert!(rule.pattern.is_match("GEMINI API ERROR: quota exhausted"));
    assert!(rule.pattern.is_match("Daily quota exceeded for project"));
    assert!(rule.pattern.is_match("rate_limit_exceeded: please wait"));

    // Negative matches (must not trigger false positives)
    assert!(!rule.pattern.is_match("Finished dev target in 0.42s"));
    assert!(!rule.pattern.is_match("Running tests for workspace"));
    assert!(!rule.pattern.is_match("Agent successfully executed command"));
}

// ── Test 10: Daemon Config Parsing and Defaults ───────────────────────────────

#[test]
fn test_daemon_config_auto_failover_structure() {
    let toml_str = r#"
[accounts.auto_failover]
enabled = true
default_cooldown_secs = 90
"#;
    let cfg: Config = toml::from_str(toml_str).expect("deserialize config");
    assert!(cfg.accounts.auto_failover.enabled);
    assert_eq!(cfg.accounts.auto_failover.default_cooldown_secs, 90);

    let default_cfg = Config::default();
    assert!(default_cfg.accounts.auto_failover.enabled);
    assert_eq!(default_cfg.accounts.auto_failover.default_cooldown_secs, 60);
}

// ── Test 11: Predecessor Terminal State Guard ─────────────────────────────────

#[tokio::test]
async fn test_predecessor_exit_event_suppression_after_handoff() {
    let account_store = AccountStore::open_in_memory().unwrap();
    let mut acct_mgr = AccountManager::new(account_store).unwrap();

    let id_a = acct_mgr
        .register(make_account("acct-a", "anthropic", vec!["mock"], 1))
        .unwrap();
    let id_b = acct_mgr
        .register(make_account("acct-b", "anthropic", vec!["mock"], 1))
        .unwrap();

    let proj_store = ProjectStore::open_in_memory().unwrap();
    let mut proj_reg = ProjectRegistry::new(proj_store).unwrap();
    let proj_id = proj_reg
        .register(make_project("proj-exit", "/tmp/ac_test_ws_exit"))
        .unwrap();

    // Predecessor emits RateLimitSignal, then after teardown emits Crashed
    let script_pred = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            40,
            AdapterEvent::RateLimitSignal {
                back_off_secs: Some(60),
            },
        ),
        ScriptedEvent::delayed(
            150,
            AdapterEvent::Crashed {
                exit_code: Some(137),
                reason: Some("Process killed by SIGKILL during stop".into()),
            },
        ),
    ];

    let script_succ = vec![
        ScriptedEvent::immediate(AdapterEvent::Ready),
        ScriptedEvent::delayed(
            10_000,
            AdapterEvent::OutputChunk {
                text: "Successor alive".into(),
                confidence: Confidence::High,
            },
        ),
    ];

    let (mgr, mut event_rx) = create_test_session_manager(
        vec![script_pred, script_succ],
        acct_mgr,
        proj_reg,
        true,
    );

    let sid1 = mgr
        .create_with_context(
            "Task testing exit suppression".into(),
            "mock".into(),
            Some(proj_id),
            Some(id_a),
        )
        .await
        .unwrap();

    mgr.start(sid1.clone()).await.unwrap();

    let timeout = tokio::time::sleep(Duration::from_millis(500));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                break;
            }
            res = event_rx.recv() => {
                let _ = res;
            }
        }
    }

    // Predecessor must remain in HandedOff, not Crashed
    let predecessor = mgr.get(sid1).await.unwrap().unwrap();
    assert_eq!(
        predecessor.state,
        SessionState::HandedOff,
        "Predecessor session must remain HandedOff and not be clobbered by exit/crash"
    );

    let successor = mgr.get(predecessor.successor_id.unwrap()).await.unwrap().unwrap();
    assert_eq!(successor.state, SessionState::Working);
    assert_eq!(successor.account_id, Some(id_b));
}
