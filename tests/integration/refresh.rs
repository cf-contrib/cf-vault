//! Renewing sessions: automatic refresh, rotation, rejection, staleness and concurrency.

use std::os::unix::fs::PermissionsExt;

use crate::helpers::{provider::Provider, *};

fn setup() -> (Provider, Workspace) {
    let provider = Provider::start();
    let ws = Workspace::new(&oauth_config(&provider.url(), free_port()));
    (provider, ws)
}

fn token_of(ws: &Workspace, args: &[&str]) -> Finished {
    let mut all = vec!["exec", "-p", "personal", "-q", "--"];
    all.extend_from_slice(args);
    run_interactive(ws, &all)
}

#[test]
fn an_expired_session_is_renewed_without_a_browser_and_the_rotation_is_saved() {
    let (provider, ws) = setup();
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        -10,
        None,
    );
    let out = token_of(&ws, &["sh", "-c", "echo $CLOUDFLARE_API_TOKEN"]);
    assert!(out.success(), "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "FAKE_ACCESS_1");
    let refreshes = provider.token_requests("refresh_token");
    assert_eq!(refreshes.len(), 1);
    assert_eq!(refreshes[0]["refresh_token"], "OLD_REFRESH");
    let stored = ws.stored("personal").unwrap();
    assert!(stored.contains("FAKE_ACCESS_1") && stored.contains("FAKE_REFRESH_1"));
    assert!(!stored.contains("OLD_REFRESH"));
}

#[test]
fn a_refresh_token_the_provider_did_not_rotate_is_kept() {
    let (provider, ws) = setup();
    provider.state.lock().unwrap().rotate_refresh = false;
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        -10,
        None,
    );
    assert!(token_of(&ws, &["true"]).success());
    assert!(ws.stored("personal").unwrap().contains("OLD_REFRESH"));
}

#[test]
fn a_rejected_refresh_does_not_start_the_command_and_clears_nothing() {
    let (provider, ws) = setup();
    provider.state.lock().unwrap().refresh_fails = true;
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        -10,
        None,
    );
    let marker = ws.path().join("started");
    let out = token_of(&ws, &["touch", &marker.display().to_string()]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("could not refresh") && out.stderr.contains("login -p personal"));
    assert!(!marker.exists());
    assert!(ws.stored("personal").unwrap().contains("OLD_REFRESH"));
    assert_no_secrets(&out.stderr, &["OLD_REFRESH"]);
}

#[test]
fn an_expired_session_without_a_refresh_token_asks_for_a_new_login() {
    let (provider, ws) = setup();
    ws.seed_oauth("personal", &provider.url(), "OLD_ACCESS", None, -10, None);
    let out = token_of(&ws, &["true"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("expired and cannot be refreshed"),
        "{}",
        out.stderr
    );
    assert!(provider.server.hits("/token").is_empty());
}

#[test]
fn a_changed_issuer_makes_the_stored_session_stale() {
    let (provider, ws) = setup();
    ws.seed_oauth(
        "personal",
        "https://another.example",
        "OLD_ACCESS",
        Some("RT"),
        3600,
        None,
    );
    let out = token_of(&ws, &["true"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("issuer or OAuth client changed"),
        "{}",
        out.stderr
    );
    assert!(provider.server.hits("/token").is_empty());
}

#[test]
fn two_simultaneous_runs_refresh_once_and_leave_a_valid_session() {
    let (provider, ws) = setup();
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        -10,
        None,
    );
    let spawn = || {
        let mut cmd = ws.std_cmd();
        cmd.env("CF_VAULT_FORCE_INTERACTIVE", "1").args([
            "exec",
            "-p",
            "personal",
            "-q",
            "--",
            "sh",
            "-c",
            "echo $CLOUDFLARE_API_TOKEN",
        ]);
        cmd.stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        cmd.spawn().unwrap()
    };
    let (a, b) = (spawn(), spawn());
    for child in [a, b] {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "FAKE_ACCESS_1");
    }
    assert_eq!(provider.token_requests("refresh_token").len(), 1);
    let stored: serde_json::Value = serde_json::from_str(&ws.stored("personal").unwrap()).unwrap();
    assert_eq!(stored["access_token"], "FAKE_ACCESS_1");
}

#[test]
fn lock_files_are_owner_only_and_hold_no_secrets() {
    let (provider, ws) = setup();
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "OLD_ACCESS",
        Some("OLD_REFRESH"),
        -10,
        None,
    );
    assert!(token_of(&ws, &["true"]).success());
    let locks = ws.path().join("state").join("locks");
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&locks), 0o700);
    let lock = locks.join("personal.lock");
    assert_eq!(mode(&lock), 0o600);
    assert_eq!(std::fs::metadata(&lock).unwrap().len(), 0);
}
