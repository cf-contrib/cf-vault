//! Noninteractive use: credentials from the environment, nothing stored, fail fast otherwise.

use std::time::{Duration, Instant};

use crate::helpers::{broker::Broker, provider::Provider, *};

const OAUTH_CONFIG: &str = "[personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
                            [personal.oauth2]\nissuer = \"http://127.0.0.1:9\"\nclient_id = \"c\"\n\
                            [ci]\ntype = \"token\"\naccount_id = \"abc123\"\n";

fn no_store(config: &str) -> Workspace {
    // The store is unavailable: any attempt to open it fails the run
    Workspace::new(config).with_env("CF_VAULT_STORE_UNAVAILABLE", "1")
}

#[test]
fn an_api_token_supplies_a_token_profile_and_an_oauth_profile_as_is_and_stores_nothing() {
    let ws = no_store(OAUTH_CONFIG);
    for profile in ["ci", "personal"] {
        let out = ws
            .cmd()
            .env("CLOUDFLARE_API_TOKEN", FAKE_ENV_TOKEN)
            .args([
                "exec",
                "-p",
                profile,
                "--",
                "sh",
                "-c",
                "echo $CLOUDFLARE_API_TOKEN",
            ])
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{profile}: {stderr}");
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), FAKE_ENV_TOKEN);
        // Without a terminal the inherited token is the credential: no override notice
        assert!(!stderr.contains("overriding"), "{stderr}");
        assert_no_secrets(&stderr, &[FAKE_ENV_TOKEN]);
    }
    assert!(std::fs::read_dir(ws.store_dir()).unwrap().next().is_none());
}

fn brokered(provider: &Provider, broker: &Broker) -> Workspace {
    let _ = provider;
    no_store(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2.exchange]\nurl = \"{}\"\nprofile = \"infra-admins:tofu-plan\"\n",
        broker.url()
    ))
}

#[test]
fn an_identity_token_is_exchanged_at_the_broker_and_released_afterwards() {
    let provider = Provider::start();
    let broker = Broker::start(vec![], "abc123");
    let ws = brokered(&provider, &broker);
    let out = ws
        .cmd()
        .env("CF_VAULT_ID_TOKEN", FAKE_ID_TOKEN_ENV)
        .args([
            "exec",
            "-p",
            "production",
            "--",
            "sh",
            "-c",
            "echo $CLOUDFLARE_API_TOKEN",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "FAKE_BROKER_TOKEN"
    );
    assert_eq!(
        broker.server.hits("/oauth/token")[0].form()["subject_token"],
        FAKE_ID_TOKEN_ENV
    );
    assert_eq!(broker.server.hits("/oauth/revoke").len(), 1);
    assert_no_secrets(
        &String::from_utf8_lossy(&out.stderr),
        &[FAKE_ID_TOKEN_ENV, "FAKE_BROKER_TOKEN"],
    );
}

#[test]
fn an_api_token_alone_is_refused_for_a_broker_profile() {
    let provider = Provider::start();
    let broker = Broker::start(vec![], "abc123");
    let ws = brokered(&provider, &broker);
    let out = ws
        .cmd()
        .env("CLOUDFLARE_API_TOKEN", FAKE_ENV_TOKEN)
        .args(["exec", "-p", "production", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("CF_VAULT_ID_TOKEN"));
    assert!(broker.server.requests().is_empty());
}

#[test]
fn the_identity_token_in_the_environment_beats_a_stored_session() {
    let provider = Provider::start();
    let broker = Broker::start(
        vec![("idp".into(), provider.url(), provider::CLIENT_ID.into())],
        "abc123",
    );
    let ws = Workspace::new(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2.exchange]\nurl = \"{}\"\nprofile = \"p\"\n",
        broker.url()
    ));
    ws.seed_oauth(
        "production",
        &provider.url(),
        "AT",
        Some("RT"),
        3600,
        Some("STORED.id.token"),
    );
    let out = ws
        .interactive()
        .env("CF_VAULT_ID_TOKEN", FAKE_ID_TOKEN_ENV)
        .args(["exec", "-p", "production", "-q", "--", "true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        broker.server.hits("/oauth/token")[0].form()["subject_token"],
        FAKE_ID_TOKEN_ENV
    );
}

#[test]
fn nothing_supplied_fails_within_seconds_and_never_waits_for_input() {
    let ws = no_store(OAUTH_CONFIG);
    for profile in ["ci", "personal"] {
        let started = Instant::now();
        let out = ws
            .cmd()
            .args(["exec", "-p", profile, "--", "true"])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(started.elapsed() < Duration::from_secs(5));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("CLOUDFLARE_API_TOKEN"), "{stderr}");
    }
}

#[test]
fn an_empty_variable_counts_as_unset() {
    let ws = no_store(OAUTH_CONFIG);
    let out = ws
        .cmd()
        .env("CLOUDFLARE_API_TOKEN", "  ")
        .args(["exec", "-p", "ci", "--", "true"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
}
