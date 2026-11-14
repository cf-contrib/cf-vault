//! A refused or failing exchange never starts the command and never falls back.

use crate::helpers::{broker::Broker, provider::Provider, *};

const PROFILE: &str = "infra-admins:tofu-plan";

fn setup() -> (Provider, Broker, Workspace) {
    let provider = Provider::start();
    let broker = Broker::start(
        vec![("idp".into(), provider.url(), provider::CLIENT_ID.into())],
        "abc123",
    );
    let ws = Workspace::new(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nredirect_port = {}\n\
         [production.oauth2.exchange]\nissuer = \"{}\"\nscopes = [\"{PROFILE}\"]\n",
        free_port(),
        broker.url()
    ));
    assert!(login(&ws, "production").success());
    (provider, broker, ws)
}

use crate::helpers::provider;

fn exec_touch(ws: &Workspace) -> (Finished, std::path::PathBuf) {
    let marker = ws.path().join("started");
    let out = run_interactive(
        ws,
        &[
            "exec",
            "-p",
            "production",
            "--",
            "touch",
            &marker.display().to_string(),
        ],
    );
    (out, marker)
}

#[test]
fn a_refused_exchange_shows_the_brokers_reason_and_starts_nothing() {
    let (provider, broker, ws) = setup();
    broker.state.lock().unwrap().fail_with.push((
        400,
        "{\"error\":\"invalid_request\",\"error_description\":\"profile infra-admins:tofu-plan is disabled\"}".into(),
    ));
    let (out, marker) = exec_touch(&ws);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr
            .contains("invalid_request: profile infra-admins:tofu-plan is disabled"),
        "{}",
        out.stderr
    );
    assert!(!marker.exists());
    // No retry for the caller's own mistakes
    assert_eq!(broker.server.hits("/oauth/token").len(), 1);
    let id_token = serde_json::from_str::<serde_json::Value>(&ws.stored("production").unwrap())
        .unwrap()["id_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_no_secrets(&out.stderr, &[&id_token, "FAKE_BROKER_TOKEN"]);
    drop(provider);
}

#[test]
fn a_503_is_retried_once_and_no_more() {
    let (_provider, broker, ws) = setup();
    broker
        .state
        .lock()
        .unwrap()
        .fail_with
        .push((503, "{\"error\":\"temporarily_unavailable\"}".into()));
    let (out, marker) = exec_touch(&ws);
    assert!(out.success(), "{}", out.stderr);
    assert!(marker.exists());
    assert_eq!(broker.server.hits("/oauth/token").len(), 2);

    let (_p, broker, ws) = setup();
    {
        let mut state = broker.state.lock().unwrap();
        state
            .fail_with
            .push((503, "{\"error\":\"temporarily_unavailable\"}".into()));
        state
            .fail_with
            .push((503, "{\"error\":\"temporarily_unavailable\"}".into()));
    }
    let (out, marker) = exec_touch(&ws);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("temporarily_unavailable"));
    assert!(!marker.exists());
    assert_eq!(broker.server.hits("/oauth/token").len(), 2);
}

#[test]
fn an_unreachable_broker_never_falls_back_to_a_weaker_credential() {
    let (provider, _broker, ws) = setup();
    let dead = format!("http://127.0.0.1:{}", free_port());
    ws.set_config(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nissuer = \"{}\"\nclient_id = \"{}\"\nredirect_port = {}\n\
         [production.oauth2.exchange]\nissuer = \"{dead}\"\nscopes = [\"{PROFILE}\"]\n",
        provider.url(),
        provider::CLIENT_ID,
        free_port()
    ));
    let marker = ws.path().join("started");
    let out = ws
        .interactive()
        .env("CLOUDFLARE_API_TOKEN", "WEAKER_TOKEN")
        .args([
            "exec",
            "-p",
            "production",
            "--",
            "touch",
            &marker.display().to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("could not reach the broker"));
    assert!(!marker.exists());
}

#[test]
fn a_failing_revocation_is_a_warning_and_the_exit_status_is_the_commands() {
    let (_provider, broker, ws) = setup();
    broker.state.lock().unwrap().revoke_status = 500;
    let out = run_interactive(
        &ws,
        &["exec", "-p", "production", "--", "sh", "-c", "exit 5"],
    );
    assert_eq!(out.code, Some(5));
    assert!(
        out.stderr.contains("warning") && out.stderr.contains("was not released"),
        "{}",
        out.stderr
    );
    assert_eq!(broker.server.hits("/oauth/revoke").len(), 1);
}
