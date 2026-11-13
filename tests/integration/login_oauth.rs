//! `login` for OAuth profiles against the scripted provider.

use crate::helpers::{provider::Provider, *};

fn setup() -> (Provider, Workspace, u16) {
    let provider = Provider::start();
    let port = free_port();
    let ws = Workspace::new(&oauth_config(&provider.url(), port));
    (provider, ws, port)
}

#[test]
fn login_stores_a_session_after_the_browser_flow() {
    let (provider, ws, port) = setup();
    let run = start_login(&ws, "personal");
    assert!(run.url.starts_with(&provider.url()), "{}", run.url);
    assert!(run.url.contains("code_challenge_method=S256"));
    run.approve();
    let out = run.finish();
    assert!(out.success(), "{}", out.stderr);
    assert!(out.stdout.contains("Logged in to profile \"personal\""));

    let stored: serde_json::Value = serde_json::from_str(&ws.stored("personal").unwrap()).unwrap();
    assert_eq!(stored["kind"], "oauth2");
    assert_eq!(stored["access_token"], "FAKE_ACCESS_1");
    assert_eq!(stored["issuer"], provider.url());
    assert_eq!(stored["client_id"], provider::CLIENT_ID);
    assert!(stored["id_token"].as_str().unwrap().contains('.'));

    let exchanges = provider.token_requests("authorization_code");
    assert_eq!(exchanges.len(), 1);
    assert_eq!(
        exchanges[0]["redirect_uri"],
        format!("http://127.0.0.1:{port}/callback")
    );
    assert!(!exchanges[0]["code_verifier"].is_empty());
}

use crate::helpers::provider;

#[test]
fn a_state_mismatch_aborts_and_stores_nothing() {
    let (_provider, ws, _) = setup();
    let run = start_login(&ws, "personal");
    run.callback_with("code=FAKE_CODE&state=evil");
    let out = run.finish();
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("expected state"), "{}", out.stderr);
    assert!(ws.stored("personal").is_none());
}

#[test]
fn an_abandoned_sign_in_times_out_and_leaves_no_session() {
    let provider = Provider::start();
    let ws = Workspace::new(&oauth_config(&provider.url(), free_port()))
        .with_env("CF_VAULT_CALLBACK_TIMEOUT_MS", "300");
    let run = start_login(&ws, "personal");
    let out = run.finish();
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("timed out"), "{}", out.stderr);
    assert!(ws.stored("personal").is_none());
}

#[test]
fn a_busy_redirect_port_gives_a_clear_error() {
    let provider = Provider::start();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = busy.local_addr().unwrap().port();
    let ws = Workspace::new(&oauth_config(&provider.url(), port));
    let out = run(&ws, &["login", "-p", "personal", "--no-browser"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr
            .contains(&format!("cannot listen on port {port}")),
        "{}",
        out.stderr
    );
    assert!(ws.stored("personal").is_none());
}

#[test]
fn login_needs_a_terminal_unless_no_browser_is_given() {
    let (_provider, ws, _) = setup();
    let out = run(&ws, &["login", "-p", "personal"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("interactive terminal"),
        "{}",
        out.stderr
    );
}

#[test]
fn the_old_session_is_replaced_only_after_the_new_sign_in_succeeds() {
    let (provider, ws, _) = setup();
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        3600,
        None,
    );
    let run = start_login(&ws, "personal");
    run.callback_with("code=FAKE_CODE&state=evil");
    assert_eq!(run.finish().code, Some(1));
    assert!(ws.stored("personal").unwrap().contains("OLD_ACCESS"));

    let out = login(&ws, "personal");
    assert!(out.success(), "{}", out.stderr);
    let stored = ws.stored("personal").unwrap();
    assert!(stored.contains("FAKE_ACCESS_1") && !stored.contains("OLD_ACCESS"));
}

#[test]
fn the_cloudflare_default_profile_explains_what_to_do_until_a_client_exists() {
    let ws = Workspace::new("[personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n");
    let out = run(&ws, &["login", "-p", "personal", "--no-browser"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("oauth2.client_id") && out.stderr.contains("type = \"token\""));
}
