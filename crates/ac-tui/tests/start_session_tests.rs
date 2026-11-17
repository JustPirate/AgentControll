//! TUI tests for the "Start Antigravity Session" form (account, permission
//! mode, working directory with TAB completion, model) and the login-link UI.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{backend::TestBackend, Terminal};

use ac_core::{
    agy_launch::{AgyExecutionMode, AgyLaunchOptions, AgyPermissionMode},
    types::{Account, Id, SessionTemplate},
};
use ac_tui::{
    app::{AgyAddStep, AgyLoginTask, AgyLoginUpdate, App, Modal},
    client::ApiClient,
    event::{handle_key, poll_agy_login},
    launch::{
        self, StartSessionForm, FIELD_ACCOUNT, FIELD_BUTTONS, FIELD_CONV_ID, FIELD_DIR,
        FIELD_EXEC_MODE, FIELD_MODEL, FIELD_PERM_MODE, FIELD_TASK_PROMPT, FIELD_TEMPLATE,
    },
    ui,
};

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn render(app: &App) -> String {
    let mut t = Terminal::new(TestBackend::new(120, 40)).unwrap();
    t.draw(|f| ui::draw(f, app)).unwrap();
    t.backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect::<Vec<_>>()
        .chunks(120)
        .map(|r| r.concat())
        .collect::<Vec<_>>()
        .join("\n")
}

/// A tree like the one in the spec, plus a file and an unreadable directory.
fn tree() -> tempfile::TempDir {
    let t = tempfile::tempdir().unwrap();
    for d in [
        "AgentControl",
        "AgentDesk/.git",
        "AgentDesk/core",
        "AgentDesk/docs",
        "AgentDesk/mobile",
        "AgentDesk/tests",
        "AgentMesh",
        "Hybrid",
        "locked",
    ] {
        std::fs::create_dir_all(t.path().join(d)).unwrap();
    }
    std::fs::write(t.path().join("notes.txt"), "not a dir").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            t.path().join("locked"),
            std::fs::Permissions::from_mode(0o000),
        )
        .unwrap();
    }
    t
}

fn setup(root: &Path) -> (App, ApiClient, Id) {
    let mut app = App::new();
    let a = Account::new(
        "vijaygovindbiju@gmail.com".into(),
        "agy".into(),
        vec!["agy".into()],
        "ref:agy:01A".into(),
        2,
        vec![],
    );
    let b = Account::new(
        "24ct406@mgits.ac.in".into(),
        "agy".into(),
        vec!["agy".into()],
        "ref:agy:01B".into(),
        2,
        vec![],
    );
    let aid = a.id.clone();
    app.accounts = vec![a, b];
    let form = StartSessionForm::new(
        root.to_path_buf(),
        root.to_path_buf(),
        AgyExecutionMode::ALL.to_vec(),
        AgyPermissionMode::ALL.to_vec(),
    );
    app.active_modal = Some(Modal::StartSession(Box::new(form)));
    let client =
        ApiClient::new(std::env::temp_dir().join(format!("no-daemon-{}.sock", ulid::Ulid::new())));
    (app, client, aid)
}

fn form(app: &App) -> &StartSessionForm {
    match &app.active_modal {
        Some(Modal::StartSession(f)) => f,
        other => panic!("form not open: {other:?}"),
    }
}

fn form_mut(app: &mut App) -> &mut StartSessionForm {
    match &mut app.active_modal {
        Some(Modal::StartSession(f)) => f,
        other => panic!("form not open: {other:?}"),
    }
}

async fn keys(app: &mut App, client: &ApiClient, ks: &[KeyCode]) {
    for k in ks {
        handle_key(app, client, press(*k)).await.unwrap();
    }
}

async fn type_str(app: &mut App, client: &ApiClient, s: &str) {
    for c in s.chars() {
        handle_key(app, client, press(KeyCode::Char(c)))
            .await
            .unwrap();
    }
}

/// Wait for background directory listings to be applied (as the tick does).
async fn settle(app: &mut App) {
    for _ in 0..300 {
        launch::poll_jobs(app);
        if !matches!(&app.active_modal, Some(Modal::StartSession(f)) if f.listing.is_some()) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("directory listing never finished");
}

async fn set_dir(app: &mut App, client: &ApiClient, s: &str) {
    form_mut(app).field = FIELD_DIR;
    form_mut(app).dir_input.clear();
    form_mut(app).completion = None;
    type_str(app, client, s).await;
}

fn popup(app: &App) -> Vec<String> {
    let f = form(app);
    f.completion
        .as_ref()
        .map(|c| {
            c.matches(launch::split_input(&f.dir_input).1)
                .into_iter()
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn tab_lists_only_child_directories_and_filters_by_typed_text() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    set_dir(&mut app, &client, "~/").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(
        popup(&app),
        [
            "AgentControl/",
            "AgentDesk/",
            "AgentMesh/",
            "Hybrid/",
            "locked/"
        ],
        "files are not listed"
    );
    let screen = render(&app);
    assert!(
        screen.contains("Tab complete")
            && screen.contains("Enter open")
            && screen.contains("AgentDesk/"),
        "{screen}"
    );

    // Typing keeps the popup and filters it (case-insensitive).
    type_str(&mut app, &client, "a").await;
    assert_eq!(popup(&app), ["AgentControl/", "AgentDesk/", "AgentMesh/"]);
    // ↓ select, Enter accepts the directory.
    keys(&mut app, &client, &[KeyCode::Down, KeyCode::Enter]).await;
    assert_eq!(form(&app).dir_input, "~/AgentDesk/");
    assert!(form(&app).completion.is_none());

    // TAB again: the children of the selected directory (hidden ones last).
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(
        popup(&app),
        ["core/", "docs/", "mobile/", "tests/", ".git/"]
    );
    // TAB cycles, Esc closes the popup but keeps the form.
    keys(&mut app, &client, &[KeyCode::Tab, KeyCode::Tab]).await;
    assert_eq!(form(&app).completion.as_ref().unwrap().selected, 2);
    keys(&mut app, &client, &[KeyCode::Esc]).await;
    assert!(form(&app).completion.is_none());
    assert_eq!(form(&app).dir_input, "~/AgentDesk/");
    assert_eq!(form(&app).resolved_dir(), t.path().join("AgentDesk"));
}

#[tokio::test]
async fn tab_completes_like_a_shell() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    // Common prefix is filled in, popup offers the candidates.
    set_dir(&mut app, &client, "~/a").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(form(&app).dir_input, "~/Agent");
    assert_eq!(popup(&app).len(), 3);

    // Unique match completes directly; nested navigation.
    set_dir(&mut app, &client, "~/hy").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(form(&app).dir_input, "~/Hybrid/");
    set_dir(&mut app, &client, "~/AgentDesk/co").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(form(&app).dir_input, "~/AgentDesk/core/");

    // Absolute and relative paths.
    set_dir(
        &mut app,
        &client,
        &format!("{}/AgentDesk/d", t.path().display()),
    )
    .await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(
        form(&app).dir_input,
        format!("{}/AgentDesk/docs/", t.path().display())
    );
    set_dir(&mut app, &client, "AgentDesk/m").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(form(&app).dir_input, "AgentDesk/mobile/");
    assert_eq!(form(&app).resolved_dir(), t.path().join("AgentDesk/mobile"));

    // No match → notice, no popup.
    set_dir(&mut app, &client, "~/zz").await;
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    settle(&mut app).await;
    assert_eq!(
        form(&app).dir_notice.as_deref(),
        Some("No matching directories")
    );
    assert!(form(&app).completion.is_none());
}

#[tokio::test]
async fn invalid_and_inaccessible_directories_are_reported_not_launched() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    set_dir(&mut app, &client, "~/does-not-exist/").await;
    assert!(render(&app).contains("not a directory"));
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(form(&app)
        .dir_notice
        .as_ref()
        .unwrap()
        .contains("does not exist"));
    // Start refuses as well.
    form_mut(&mut app).field = FIELD_BUTTONS;
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(form(&app)
        .error
        .as_ref()
        .unwrap()
        .contains("does not exist"));
    assert!(app.status_message.is_none(), "nothing was launched");

    #[cfg(unix)]
    if !nix_is_root() {
        set_dir(&mut app, &client, "~/locked/").await;
        keys(&mut app, &client, &[KeyCode::Tab]).await;
        settle(&mut app).await;
        assert!(
            form(&app)
                .dir_notice
                .as_ref()
                .unwrap()
                .contains("Permission denied"),
            "{:?}",
            form(&app).dir_notice
        );
        keys(&mut app, &client, &[KeyCode::Enter]).await;
        assert!(form(&app)
            .dir_notice
            .as_ref()
            .unwrap()
            .contains("not accessible"));
    }

    // A file is not a directory.
    set_dir(&mut app, &client, "~/notes.txt").await;
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(form(&app)
        .dir_notice
        .as_ref()
        .unwrap()
        .contains("does not exist"));

    // Manual entry of a valid path without completion is accepted and normalised.
    set_dir(&mut app, &client, "~/AgentDesk/../Hybrid").await;
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(form(&app).dir_input, "~/Hybrid");
    assert_eq!(form(&app).field, FIELD_EXEC_MODE);
}

#[cfg(unix)]
fn nix_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .map(|s| {
            s.lines()
                .any(|l| l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some("0"))
        })
        .unwrap_or(false)
}

#[tokio::test]
async fn permission_mode_account_and_model_selection_build_the_launch_options() {
    let t = tree();
    let (mut app, client, aid) = setup(t.path());
    let b = app.accounts[1].id.clone();
    app.agy_models.insert(
        b.0.clone(),
        Some(Ok(vec![(
            "gemini-3.8-flash-medium".into(),
            "Gemini 3.8 Flash (Medium)".into(),
        )])),
    );

    // Defaults: first account, Default exec mode, Normal perm mode, the TUI's directory, agy's default model.
    let o = launch::launch_options(&app, form(&app)).unwrap();
    assert_eq!(o.execution_mode, AgyExecutionMode::Default);
    assert_eq!(o.permission_mode, AgyPermissionMode::Normal);
    assert_eq!(o.model, None);
    assert_eq!(PathBuf::from(o.working_dir.unwrap()), t.path());
    assert_eq!(launch::agy_accounts(&app)[form(&app).account_index].id, aid);

    // Account: →, including the "+ Add" entry, wraps around.
    form_mut(&mut app).field = FIELD_ACCOUNT;
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(launch::agy_accounts(&app)[form(&app).account_index].id, b);
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert!(render(&app).contains("+ Add Antigravity Account"));
    keys(&mut app, &client, &[KeyCode::Right, KeyCode::Right]).await;
    assert_eq!(launch::agy_accounts(&app)[form(&app).account_index].id, b);

    // Execution mode selection: Default, Accept Edits, Plan.
    form_mut(&mut app).field = FIELD_EXEC_MODE;
    for m in &AgyExecutionMode::ALL[1..] {
        keys(&mut app, &client, &[KeyCode::Right]).await;
        assert_eq!(form(&app).exec_mode(), *m);
        assert!(render(&app).contains(m.label()));
    }
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(
        form(&app).exec_mode(),
        AgyExecutionMode::Default,
        "wraps back to Default"
    );
    keys(&mut app, &client, &[KeyCode::Right, KeyCode::Right]).await; // Selects Plan

    // Permission / Access mode selection: Normal, Dangerously Skip Permissions.
    form_mut(&mut app).field = FIELD_PERM_MODE;
    for m in &AgyPermissionMode::ALL[1..] {
        keys(&mut app, &client, &[KeyCode::Right]).await;
        assert_eq!(form(&app).perm_mode(), *m);
        assert!(render(&app).contains(m.label()));
    }
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(
        form(&app).perm_mode(),
        AgyPermissionMode::Normal,
        "wraps back to Normal"
    );

    form_mut(&mut app).field = FIELD_MODEL;
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert!(render(&app).contains("Gemini 3.8 Flash (Medium)"));
    let o = launch::launch_options(&app, form(&app)).unwrap();
    assert_eq!(o.execution_mode, AgyExecutionMode::Plan);
    assert_eq!(o.permission_mode, AgyPermissionMode::Normal);
    assert_eq!(o.model.as_deref(), Some("gemini-3.8-flash-medium"));
}

#[tokio::test]
async fn dangerous_mode_requires_explicit_confirmation() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    form_mut(&mut app).perm_mode_index = AgyPermissionMode::ALL
        .iter()
        .position(|m| m.is_dangerous())
        .unwrap();
    form_mut(&mut app).field = FIELD_BUTTONS;

    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(
        form(&app).confirm_dangerous,
        Some(0),
        "Cancel is focused by default"
    );
    let screen = render(&app);
    assert!(
        screen.contains("Dangerously Skip Permissions")
            && screen.contains("automatically approve")
            && screen.contains("[ Continue ]")
    );
    assert!(app.status_message.is_none(), "not launched yet");

    // Enter on Cancel returns to the form without launching.
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(form(&app).confirm_dangerous, None);
    assert!(app.status_message.is_none());
    // Esc also backs out.
    keys(&mut app, &client, &[KeyCode::Enter, KeyCode::Esc]).await;
    assert!(app.active_modal.is_some() && app.status_message.is_none());

    // Continue launches (the unreachable test daemon reports the attempt).
    keys(
        &mut app,
        &client,
        &[KeyCode::Enter, KeyCode::Right, KeyCode::Enter],
    )
    .await;
    assert!(app.active_modal.is_none());
    assert!(app
        .status_message
        .as_ref()
        .unwrap()
        .0
        .contains("Failed to create session"));
}

#[tokio::test]
async fn safe_modes_launch_without_a_confirmation_and_esc_cancels() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    let screen = render(&app);
    for s in [
        "Start Antigravity Session",
        "Account",
        "vijaygovindbiju@gmail.com",
        "Execution Mode",
        "Default",
        "Permission / Access",
        "Normal",
        "Working Directory",
        "Resolved:",
        "[ TAB completion ]",
        "Model",
        "Default (agy setting)",
        "[ Start Session ]",
        "[ Cancel ]",
    ] {
        assert!(screen.contains(s), "missing {s:?}\n{screen}");
    }
    keys(&mut app, &client, &[KeyCode::Esc]).await;
    assert!(app.active_modal.is_none() && app.status_message.is_none());

    let (mut app, client, _) = setup(t.path());
    form_mut(&mut app).exec_mode_index = 2; // Plan
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(
        app.active_modal.is_none(),
        "no confirmation for non-dangerous modes"
    );
    assert!(app
        .status_message
        .as_ref()
        .unwrap()
        .0
        .contains("Failed to create session"));
}

#[tokio::test]
async fn adding_an_account_from_the_form_returns_to_it() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    form_mut(&mut app).field = FIELD_ACCOUNT;
    form_mut(&mut app).account_index = 2; // "+ Add Antigravity Account"
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(matches!(
        &app.active_modal,
        Some(Modal::AgyAddAccount {
            step: AgyAddStep::Name { .. },
            ..
        })
    ));
    keys(&mut app, &client, &[KeyCode::Esc]).await;
    assert!(
        matches!(&app.active_modal, Some(Modal::StartSession(_))),
        "cancel returns to the form"
    );
}

#[tokio::test]
async fn login_link_screen_masks_pasted_address_and_forwards_it() {
    let (mut app, client, _) = setup(Path::new("/"));
    app.agy_add_method = 0;
    app.active_modal = Some(Modal::AgyAddAccount {
        label: "Phone".into(),
        step: AgyAddStep::Method,
    });
    keys(&mut app, &client, &[KeyCode::Down]).await;
    assert!(render(&app).contains("Get a link to open on another device"));

    let updates: std::sync::Arc<std::sync::Mutex<Vec<AgyLoginUpdate>>> = Default::default();
    let task = tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_secs(60)).await });
    app.agy_login = Some(AgyLoginTask {
        abort: task.abort_handle(),
        updates: updates.clone(),
    });
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    app.agy_login_paste = Some(tx);
    updates.lock().unwrap().push(AgyLoginUpdate::LinkReady {
        url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=S".into(),
        phone_url: None,
    });
    poll_agy_login(&mut app, &client).await;
    let screen = render(&app);
    assert!(
        screen.contains("Login Link")
            && screen.contains("Copy Link")
            && screen.contains("Waiting for authentication")
            && screen.contains("single use"),
        "{screen}"
    );

    let pasted = "http://127.0.0.1:4242/oauth2callback?state=S&code=4/0SECRETCODE";
    type_str(&mut app, &client, pasted).await;
    let screen = render(&app);
    assert!(
        !screen.contains("SECRETCODE") && screen.contains("chars)"),
        "pasted code must be masked"
    );
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(rx.recv().await.unwrap(), pasted);
    assert!(render(&app).contains("Verifying"));

    updates.lock().unwrap().push(AgyLoginUpdate::PasteRejected {
        reason: "Invalid OAuth state.".into(),
    });
    poll_agy_login(&mut app, &client).await;
    assert!(render(&app).contains("Not accepted: Invalid OAuth state."));

    // Cancel invalidates the pending login (task aborted, paste channel dropped).
    keys(&mut app, &client, &[KeyCode::Esc]).await;
    assert!(app.agy_login.is_none() && app.agy_login_paste.is_none());
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(rx.recv().await.is_none(), "paste channel closed");
}

#[tokio::test]
async fn login_link_screen_displays_phone_portal_and_toggles_qr_code() {
    let (mut app, client, _) = setup(Path::new("/"));
    app.active_modal = Some(Modal::AgyAddAccount {
        label: "Phone".into(),
        step: AgyAddStep::Method,
    });
    let updates: std::sync::Arc<std::sync::Mutex<Vec<AgyLoginUpdate>>> = Default::default();
    let task = tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_secs(60)).await });
    app.agy_login = Some(AgyLoginTask {
        abort: task.abort_handle(),
        updates: updates.clone(),
    });
    let (tx, _rx) = tokio::sync::mpsc::channel(4);
    app.agy_login_paste = Some(tx);
    updates.lock().unwrap().push(AgyLoginUpdate::LinkReady {
        url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=x&state=S".into(),
        phone_url: Some("http://10.0.0.5:45678/phone".into()),
    });
    poll_agy_login(&mut app, &client).await;

    // By default, displays Phone Portal, link, and Show QR Code button
    let screen = render(&app);
    assert!(screen.contains("Phone Sign-in Portal"), "{screen}");
    assert!(screen.contains("http://10.0.0.5:45678/phone"), "{screen}");
    assert!(screen.contains("Show QR Code"), "{screen}");

    // Tab key toggles QR code view
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    let screen_qr = render(&app);
    assert!(
        screen_qr.contains("Scan with your phone camera to sign in:"),
        "{screen_qr}"
    );
    assert!(screen_qr.contains("Phone Portal:"), "{screen_qr}");

    // Tab key again toggles back to details
    keys(&mut app, &client, &[KeyCode::Tab]).await;
    let screen_details = render(&app);
    assert!(
        screen_details.contains("Phone Sign-in Portal"),
        "{screen_details}"
    );
    assert!(
        !screen_details.contains("Scan with your phone camera"),
        "{screen_details}"
    );

    // Clean up
    keys(&mut app, &client, &[KeyCode::Esc]).await;
}

#[tokio::test]
async fn test_resume_conversation_id_field_typing_and_editing() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());

    form_mut(&mut app).field = FIELD_CONV_ID;
    assert_eq!(form(&app).conversation_input, "");

    // Type valid conversation ID
    type_str(&mut app, &client, "conv-abc-123").await;
    assert_eq!(form(&app).conversation_input, "conv-abc-123");

    // Backspace removes last char
    keys(&mut app, &client, &[KeyCode::Backspace]).await;
    assert_eq!(form(&app).conversation_input, "conv-abc-12");

    // Delete removes last char
    keys(&mut app, &client, &[KeyCode::Delete]).await;
    assert_eq!(form(&app).conversation_input, "conv-abc-1");

    // Render should show the label and the typed value
    let screen = render(&app);
    assert!(screen.contains("Resume Conversation ID"), "{screen}");
    assert!(screen.contains("conv-abc-1"), "{screen}");
}

#[tokio::test]
async fn test_resume_conversation_id_validation_error() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());

    // Enter invalid conversation ID (starts with dash)
    form_mut(&mut app).field = FIELD_CONV_ID;
    type_str(&mut app, &client, "-invalid-id").await;

    // Focus Start button
    form_mut(&mut app).field = FIELD_BUTTONS;
    form_mut(&mut app).button = 0;

    // Press Enter to submit
    keys(&mut app, &client, &[KeyCode::Enter]).await;

    let error = form(&app).error.as_ref().expect("Should have validation error");
    assert!(
        error.contains("Invalid conversation ID"),
        "Expected invalid conversation error, got: {error}"
    );
}

#[tokio::test]
async fn test_resume_conversation_id_in_launch_options() {
    let t = tree();
    let (mut app, _, _) = setup(t.path());

    // Initially empty -> conversation_id is None
    let opts = launch::launch_options(&app, form(&app)).unwrap();
    assert_eq!(opts.conversation_id, None);

    // When valid conversation ID is populated -> conversation_id is Some(...)
    form_mut(&mut app).conversation_input = "valid-conv-id-123".into();
    let opts = launch::launch_options(&app, form(&app)).unwrap();
    assert_eq!(opts.conversation_id, Some("valid-conv-id-123".into()));
}

#[tokio::test]
async fn test_resume_conversation_id_paste() {
    let t = tree();
    let (mut app, _, _) = setup(t.path());

    form_mut(&mut app).field = FIELD_CONV_ID;
    let form_box = match app.active_modal.take() {
        Some(Modal::StartSession(f)) => f,
        _ => unreachable!(),
    };
    launch::handle_paste(&mut app, form_box, "  conv-pasted-999 \t\n");
    assert_eq!(form(&app).conversation_input, "conv-pasted-999");
}

fn make_test_template(
    name: &str,
    description: Option<&str>,
    agent_type: &str,
    prompt: Option<&str>,
    account_tag: Option<&str>,
    permission_mode: Option<&str>,
    model: Option<&str>,
    launch_options: Option<AgyLaunchOptions>,
) -> SessionTemplate {
    SessionTemplate {
        id: Id::new(),
        name: name.to_string(),
        description: description.map(str::to_string),
        agent_type: agent_type.to_string(),
        default_task_prompt: prompt.map(str::to_string),
        account_tag: account_tag.map(str::to_string),
        permission_mode: permission_mode.map(str::to_string),
        model: model.map(str::to_string),
        launch_options,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[tokio::test]
async fn test_template_cycling_and_auto_population() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    let b_id = app.accounts[1].id.clone();

    // Cache model for account 1
    app.agy_models.insert(
        b_id.0.clone(),
        Some(Ok(vec![(
            "gemini-3.8-flash-medium".into(),
            "Gemini 3.8 Flash (Medium)".into(),
        )])),
    );

    let t1 = make_test_template(
        "code-review",
        Some("Automated code review"),
        "agy",
        Some("Perform code review on latest commits"),
        Some("24ct406@mgits.ac.in"),
        Some("normal"),
        Some("gemini-3.8-flash-medium"),
        Some(AgyLaunchOptions {
            execution_mode: AgyExecutionMode::Plan,
            permission_mode: AgyPermissionMode::Normal,
            sandbox: false,
            model: None,
            working_dir: None,
            conversation_id: None,
            initial_rows: None,
            initial_cols: None,
        }),
    );

    let t2 = make_test_template(
        "security-audit",
        Some("Security audit with elevated permissions"),
        "agy",
        Some("Run security vulnerability scan"),
        None,
        Some("dangerously_skip_permissions"),
        None,
        None,
    );

    app.templates = vec![t1, t2];

    // Initial state: custom session mode
    assert_eq!(form(&app).field, FIELD_TEMPLATE);
    assert_eq!(form(&app).template_index, 0);
    assert_eq!(form(&app).task_prompt, "");
    let screen = render(&app);
    assert!(screen.contains("Template"), "{screen}");
    assert!(screen.contains("(None - custom session)"), "{screen}");

    // Press Right to select template 1 (code-review)
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).template_index, 1);
    assert_eq!(form(&app).task_prompt, "Perform code review on latest commits");
    assert_eq!(form(&app).account_index, 1); // matched 24ct406@mgits.ac.in
    assert_eq!(form(&app).exec_mode(), AgyExecutionMode::Plan);
    assert_eq!(form(&app).perm_mode(), AgyPermissionMode::Normal);
    assert_eq!(form(&app).model_index, 1); // matched gemini-3.8-flash-medium

    let screen = render(&app);
    assert!(screen.contains("code-review"), "{screen}");
    assert!(screen.contains("Automated code review"), "{screen}");
    assert!(screen.contains("Perform code review on latest commits"), "{screen}");

    // Press Right to select template 2 (security-audit)
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).template_index, 2);
    assert_eq!(form(&app).task_prompt, "Run security vulnerability scan");
    assert_eq!(form(&app).perm_mode(), AgyPermissionMode::DangerouslySkipPermissions);

    let screen = render(&app);
    assert!(screen.contains("security-audit"), "{screen}");
    assert!(screen.contains("Security audit with elevated permissions"), "{screen}");
    assert!(screen.contains("Run security vulnerability scan"), "{screen}");
}

#[tokio::test]
async fn test_template_task_prompt_user_override() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());

    let t1 = make_test_template(
        "test-runner",
        Some("Run test suite"),
        "agy",
        Some("cargo test"),
        None,
        Some("normal"),
        None,
        None,
    );
    app.templates = vec![t1];

    // Select template 1
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).task_prompt, "cargo test");

    // Focus FIELD_TASK_PROMPT and type extra arguments
    form_mut(&mut app).field = FIELD_TASK_PROMPT;
    type_str(&mut app, &client, " --lib").await;
    assert_eq!(form(&app).task_prompt, "cargo test --lib");

    // Backspace removes last char
    keys(&mut app, &client, &[KeyCode::Backspace]).await;
    assert_eq!(form(&app).task_prompt, "cargo test --li");

    // Delete removes last char
    keys(&mut app, &client, &[KeyCode::Delete]).await;
    assert_eq!(form(&app).task_prompt, "cargo test --l");

    // Also override execution mode
    form_mut(&mut app).field = FIELD_EXEC_MODE;
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).exec_mode(), AgyExecutionMode::AcceptEdits);

    let screen = render(&app);
    assert!(screen.contains("cargo test --l"), "{screen}");
}

#[tokio::test]
async fn test_template_dangerous_mode_requires_confirmation() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());

    let t_danger = make_test_template(
        "auto-fix",
        Some("Autonomous fix mode"),
        "agy",
        Some("fix compiler errors"),
        None,
        Some("dangerously-skip-permissions"),
        None,
        None,
    );
    app.templates = vec![t_danger];

    // Select template 1
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).perm_mode(), AgyPermissionMode::DangerouslySkipPermissions);

    // Press Enter to submit from FIELD_TEMPLATE
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(form(&app).confirm_dangerous, Some(0), "Cancel should be default focused button");

    let screen = render(&app);
    assert!(screen.contains("Dangerously Skip Permissions") || screen.contains("Dangerous Mode"), "{screen}");

    // Cancel confirmation via Esc
    keys(&mut app, &client, &[KeyCode::Esc]).await;
    assert_eq!(form(&app).confirm_dangerous, None);
    assert!(app.active_modal.is_some());

    // Press Enter again to re-open confirmation
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert_eq!(form(&app).confirm_dangerous, Some(0));

    // Toggle to Continue (1)
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).confirm_dangerous, Some(1));

    // Press Enter to launch
    keys(&mut app, &client, &[KeyCode::Enter]).await;
    assert!(app.active_modal.is_none(), "Session launched after explicit dangerous confirmation");
}

#[tokio::test]
async fn test_template_options_wrap_around() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());

    let t1 = make_test_template("t1", None, "agy", None, None, None, None, None);
    let t2 = make_test_template("t2", None, "agy", None, None, None, None, None);
    app.templates = vec![t1, t2];

    assert_eq!(form(&app).template_index, 0);

    // Left from 0 wraps to 2
    keys(&mut app, &client, &[KeyCode::Left]).await;
    assert_eq!(form(&app).template_index, 2);

    // Left from 2 goes to 1
    keys(&mut app, &client, &[KeyCode::Left]).await;
    assert_eq!(form(&app).template_index, 1);

    // Left from 1 goes to 0
    keys(&mut app, &client, &[KeyCode::Left]).await;
    assert_eq!(form(&app).template_index, 0);

    // Right from 0 goes to 1
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).template_index, 1);

    // Right from 1 goes to 2
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).template_index, 2);

    // Right from 2 wraps to 0
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).template_index, 0);
}

#[tokio::test]
async fn test_template_task_prompt_paste() {
    let t = tree();
    let (mut app, _, _) = setup(t.path());

    form_mut(&mut app).field = FIELD_TASK_PROMPT;
    let form_box = match app.active_modal.take() {
        Some(Modal::StartSession(f)) => f,
        _ => unreachable!(),
    };
    launch::handle_paste(&mut app, form_box, "Refactor database migrations\r\n");
    assert_eq!(form(&app).task_prompt, "Refactor database migrations");
}

#[tokio::test]
async fn test_template_pending_model_resolution_on_job_completion() {
    let t = tree();
    let (mut app, client, _) = setup(t.path());
    let a_id = app.accounts[0].id.clone();

    let t1 = make_test_template(
        "model-template",
        None,
        "agy",
        None,
        None,
        None,
        Some("gemini-pro-preview"),
        None,
    );
    app.templates = vec![t1];

    // Select template 1
    keys(&mut app, &client, &[KeyCode::Right]).await;
    assert_eq!(form(&app).pending_model, Some("gemini-pro-preview".into()));
    assert_eq!(form(&app).model_index, 0, "Model not loaded yet, index remains 0");

    // Deliver background JobResult::Models
    app.launch_jobs.lock().unwrap().push(launch::JobResult::Models {
        account_id: a_id.0.clone(),
        result: Ok(vec![
            ("gemini-flash".into(), "Gemini Flash".into()),
            ("gemini-pro-preview".into(), "Gemini Pro Preview".into()),
        ]),
    });
    launch::poll_jobs(&mut app);

    assert_eq!(form(&app).model_index, 2, "pending_model resolved to index 2");
}

#[tokio::test]
async fn test_api_client_template_methods() {
    let client = ApiClient::new(std::env::temp_dir().join(format!("no-daemon-{}.sock", ulid::Ulid::new())));
    
    // Check list_templates with unreachable daemon returns ClientError::DaemonUnavailable
    let list_res = client.list_templates().await;
    assert!(matches!(list_res, Err(ac_tui::client::ClientError::DaemonUnavailable(_, _))));

    // Check get_template with unreachable daemon
    let get_res = client.get_template("my-template").await;
    assert!(matches!(get_res, Err(ac_tui::client::ClientError::DaemonUnavailable(_, _))));

    // Check create_session_from_template with unreachable daemon
    let create_res = client.create_session_from_template("my-template", Some("task"), None, None, None, true).await;
    assert!(matches!(create_res, Err(ac_tui::client::ClientError::DaemonUnavailable(_, _))));
}
