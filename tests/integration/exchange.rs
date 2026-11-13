//! Broker exchange: discovery, the request, what is delivered, and what is released.

use crate::helpers::{broker::Broker, provider::Provider, *};

const PROFILE: &str = "infra-admins:tofu-plan";

struct Setup {
    provider: Provider,
    broker: Broker,
    ws: Workspace,
}

/// An exchange-only profile: the provider and client come from the broker's metadata.
fn exchange_only() -> Setup {
    let provider = Provider::start();
    let broker = Broker::start(
        vec![(
            "com.example.idp".into(),
            provider.url(),
            provider::CLIENT_ID.into(),
        )],
        "abc123",
    );
    let ws = Workspace::new(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nredirect_port = {}\n\
         [production.oauth2.exchange]\nurl = \"{}\"\nprofile = \"{PROFILE}\"\n",
        free_port(),
        broker.url()
    ));
    Setup {
        provider,
        broker,
        ws,
    }
}

use crate::helpers::provider;

fn exec(ws: &Workspace, extra: &[&str], command: &[&str]) -> Finished {
    let mut args = vec!["exec", "-p", "production"];
    args.extend_from_slice(extra);
    args.push("--");
    args.extend_from_slice(command);
    run_interactive(ws, &args)
}

#[test]
fn the_provider_is_discovered_and_the_command_gets_the_broker_token() {
    let s = exchange_only();
    let out = login(&s.ws, "production");
    assert!(out.success(), "{}", out.stderr);
    let stored: serde_json::Value =
        serde_json::from_str(&s.ws.stored("production").unwrap()).unwrap();
    assert_eq!(stored["issuer"], s.provider.url());

    let out = exec(&s.ws, &[], &["env"]);
    assert!(out.success(), "{}", out.stderr);
    assert!(out
        .stdout
        .contains("CLOUDFLARE_API_TOKEN=FAKE_BROKER_TOKEN"));
    assert!(out.stdout.contains("CLOUDFLARE_ACCOUNT_ID=abc123"));
    // FR-016: the stored identity and refresh tokens never reach the command
    let id_token = stored["id_token"].as_str().unwrap();
    let refresh = stored["refresh_token"].as_str().unwrap();
    assert_no_secrets(
        &out.stdout,
        &[id_token, refresh, stored["access_token"].as_str().unwrap()],
    );

    let exchanges = s.broker.server.hits("/oauth/token");
    assert_eq!(exchanges.len(), 1);
    let form = exchanges[0].form();
    assert_eq!(
        form["grant_type"],
        "urn:ietf:params:oauth:grant-type:token-exchange"
    );
    assert_eq!(form["subject_token"], id_token);
    assert_eq!(
        form["subject_token_type"],
        "urn:ietf:params:oauth:token-type:id_token"
    );
    assert_eq!(form["profile"], PROFILE);
    assert!(!form.contains_key("ttl") && !form.contains_key("audience"));

    // Released after the command exited
    let revokes = s.broker.server.hits("/oauth/revoke");
    assert_eq!(revokes.len(), 1);
    assert_eq!(revokes[0].form()["token"], "FAKE_BROKER_TOKEN");
    assert_eq!(revokes[0].form()["token_type_hint"], "access_token");
    assert!(
        out.stderr.contains("released token 3f2a…"),
        "{}",
        out.stderr
    );
    assert_no_secrets(&out.stderr, &["FAKE_BROKER_TOKEN"]);
}

#[test]
fn ttl_is_sent_only_when_given() {
    let s = exchange_only();
    assert!(login(&s.ws, "production").success());
    assert!(exec(&s.ws, &["--ttl", "10m"], &["true"]).success());
    assert_eq!(s.broker.server.hits("/oauth/token")[0].form()["ttl"], "10m");
}

#[test]
fn several_providers_need_a_name_and_none_is_an_error() {
    let s = exchange_only();
    {
        let mut state = s.broker.state.lock().unwrap();
        state.providers.push((
            "com.example.other".into(),
            "https://other.example".into(),
            "x".into(),
        ));
    }
    let out = run(&s.ws, &["login", "-p", "production", "--no-browser"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("com.example.idp, com.example.other"));
    assert!(out.stderr.contains("oauth2.exchange.provider"));

    s.ws.set_config(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nredirect_port = {}\n\
         [production.oauth2.exchange]\nurl = \"{}\"\nprofile = \"{PROFILE}\"\nprovider = \"com.example.idp\"\n",
        free_port(),
        s.broker.url()
    ));
    assert!(login(&s.ws, "production").success());

    s.broker.state.lock().unwrap().providers.clear();
    let out = run(&s.ws, &["login", "-p", "production", "--no-browser"]);
    assert!(
        out.stderr.contains("lists no identity providers"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_bucket_only_profile_delivers_r2_and_no_token_and_revokes_nothing() {
    let s = exchange_only();
    {
        let mut state = s.broker.state.lock().unwrap();
        state.with_token = false;
        state.with_bucket = true;
    }
    assert!(login(&s.ws, "production").success());
    let mut cmd = s.ws.interactive();
    cmd.env("CLOUDFLARE_API_TOKEN", "STALE_INHERITED");
    let out = cmd
        .args(["exec", "-p", "production", "--", "env"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(!stdout.contains("CLOUDFLARE_API_TOKEN="), "{stdout}");
    for expected in [
        "CLOUDFLARE_R2_ACCESS_KEY_ID=FAKE_R2_KEY",
        "CLOUDFLARE_R2_SECRET_ACCESS_KEY=FAKE_R2_SECRET",
        "CLOUDFLARE_R2_SESSION_TOKEN=FAKE_R2_SESSION",
        "CLOUDFLARE_R2_ENDPOINT=https://abc.r2.cloudflarestorage.com",
        "CLOUDFLARE_R2_BUCKET=org-state",
    ] {
        assert!(stdout.contains(expected), "missing {expected} in {stdout}");
    }
    assert!(s.broker.server.hits("/oauth/revoke").is_empty());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("can't be revoked"), "{stderr}");
}

#[test]
fn a_profile_with_a_token_and_a_bucket_delivers_both() {
    let s = exchange_only();
    s.broker.state.lock().unwrap().with_bucket = true;
    assert!(login(&s.ws, "production").success());
    let out = exec(&s.ws, &[], &["env"]);
    assert!(out
        .stdout
        .contains("CLOUDFLARE_API_TOKEN=FAKE_BROKER_TOKEN"));
    assert!(out.stdout.contains("CLOUDFLARE_R2_BUCKET=org-state"));
    assert_eq!(s.broker.server.hits("/oauth/revoke").len(), 1);
}

#[test]
fn an_account_mismatch_stops_before_the_command_and_releases_the_token() {
    let s = exchange_only();
    s.broker.state.lock().unwrap().account_id = "someone-else".into();
    assert!(login(&s.ws, "production").success());
    let marker = s.ws.path().join("started");
    let out = exec(&s.ws, &[], &["touch", &marker.display().to_string()]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("someone-else") && out.stderr.contains("abc123"));
    assert!(out.stderr.contains("profile \"production\""));
    assert!(!marker.exists());
    assert_eq!(s.broker.server.hits("/oauth/revoke").len(), 1);
    assert_no_secrets(&out.stderr, &["FAKE_BROKER_TOKEN"]);
}

#[test]
fn an_explicit_provider_plus_exchange_signs_in_there_and_exchanges_its_id_token() {
    let provider = Provider::start();
    // The broker lists a different provider; the profile's own settings win
    let broker = Broker::start(
        vec![(
            "ignored".into(),
            "https://ignored.example".into(),
            "x".into(),
        )],
        "abc123",
    );
    let ws = Workspace::new(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nissuer = \"{}\"\nclient_id = \"{}\"\nredirect_port = {}\n\
         [production.oauth2.exchange]\nurl = \"{}\"\nprofile = \"{PROFILE}\"\n",
        provider.url(),
        provider::CLIENT_ID,
        free_port(),
        broker.url()
    ));
    assert!(login(&ws, "production").success());
    let out = exec(&ws, &[], &["sh", "-c", "echo $CLOUDFLARE_API_TOKEN"]);
    assert!(out.success(), "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "FAKE_BROKER_TOKEN");
    assert_eq!(broker.server.hits("/oauth/token").len(), 1);
}

#[test]
fn a_provider_without_an_id_token_cannot_be_used_with_a_broker() {
    let s = exchange_only();
    s.provider.state.lock().unwrap().issue_id_token = false;
    let out = login(&s.ws, "production");
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("no ID token"), "{}", out.stderr);
    assert!(s.ws.stored("production").is_none());
}
