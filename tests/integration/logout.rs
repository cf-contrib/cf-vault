//! `logout`: the local session goes first, the provider is told on a best-effort basis.

use crate::helpers::{provider::Provider, *};

#[test]
fn logout_removes_the_session_revokes_the_token_and_stops_later_runs() {
    let provider = Provider::start();
    let ws = Workspace::new(&oauth_config(&provider.url(), free_port()));
    ws.seed_oauth(
        "personal",
        &provider.url(),
        "AT",
        Some("FAKE_REFRESH_TO_REVOKE"),
        3600,
        None,
    );
    let out = run(&ws, &["logout", "-p", "personal"]);
    assert!(out.success(), "{}", out.stderr);
    assert!(ws.stored("personal").is_none());
    let revokes = provider.server.hits("/revoke");
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].form()["token"], "FAKE_REFRESH_TO_REVOKE");

    let marker = ws.path().join("started");
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "--",
            "touch",
            &marker.display().to_string(),
        ],
    );
    assert_eq!(out.code, Some(1));
    assert!(!marker.exists());
}

#[test]
fn logout_succeeds_when_nothing_is_stored() {
    let provider = Provider::start();
    let ws = Workspace::new(&oauth_config(&provider.url(), free_port()));
    let out = run(&ws, &["logout", "-p", "personal"]);
    assert!(out.success(), "{}", out.stderr);
    assert!(out.stdout.contains("no stored session"));
}

#[test]
fn a_failing_revocation_is_a_warning_and_the_session_is_still_removed() {
    // Nothing listens on the issuer's port
    let dead = format!("http://127.0.0.1:{}", free_port());
    let ws = Workspace::new(&oauth_config(&dead, free_port()));
    ws.seed_oauth("personal", &dead, "AT", Some("RT"), 3600, None);
    let out = run(&ws, &["logout", "-p", "personal"]);
    assert!(out.success(), "{}", out.stderr);
    assert!(out.stderr.contains("warning") && out.stderr.contains("not revoked"));
    assert!(ws.stored("personal").is_none());
}

#[test]
fn logout_of_a_token_profile_just_deletes_the_token() {
    let ws = Workspace::new("[ci]\ntype = \"token\"\naccount_id = \"abc123\"\n");
    ws.seed_token("ci", FAKE_TOKEN);
    let out = run(&ws, &["logout", "-p", "ci"]);
    assert!(out.success());
    assert!(ws.stored("ci").is_none());
}
