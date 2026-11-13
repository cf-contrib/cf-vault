//! Direct R2 credentials from a static token, against a scripted Cloudflare API.

use crate::helpers::{cloudflare::Cloudflare, *};

fn config(extra: &str) -> String {
    format!(
        "[ci-state]\ntype = \"token\"\naccount_id = \"abc123\"\n\
         [ci-state.r2]\nbucket = \"tf-state\"\n{extra}"
    )
}

fn setup(extra: &str) -> (Cloudflare, Workspace) {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(&config(extra)).with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_token("ci-state", FAKE_TOKEN);
    (cloudflare, ws)
}

fn body_of(cf: &Cloudflare) -> serde_json::Value {
    let hits = cf
        .server
        .hits("/accounts/abc123/r2/temp-access-credentials");
    assert_eq!(hits.len(), 1);
    serde_json::from_str(&hits[0].body).unwrap()
}

#[test]
fn the_request_names_the_bucket_and_the_parent_and_carries_the_defaults() {
    let (cf, ws) = setup("");
    let out = run_interactive(&ws, &["exec", "-p", "ci-state", "--", "true"]);
    assert!(out.success(), "{}", out.stderr);
    let body = body_of(&cf);
    assert_eq!(body["bucket"], "tf-state");
    assert_eq!(body["parentAccessKeyId"], "FAKE_TOKEN_ID");
    assert_eq!(body["permission"], "object-read-write");
    assert_eq!(body["ttlSeconds"], 900);
    assert!(body.get("prefixes").is_none());
    // The parent token is the bearer; its secret half is never sent anywhere
    let verify = &cf.server.hits("/accounts/abc123/tokens/verify")[0];
    assert_eq!(
        verify.header("authorization"),
        Some(format!("Bearer {FAKE_TOKEN}").as_str())
    );
    let create = &cf
        .server
        .hits("/accounts/abc123/r2/temp-access-credentials")[0];
    assert_eq!(
        create.header("authorization"),
        Some(format!("Bearer {FAKE_TOKEN}").as_str())
    );
}

#[test]
fn ttl_permission_and_prefixes_are_honoured() {
    let (cf, ws) = setup("permission = \"object-read-only\"\nprefixes = [\"repo/\", \"other/\"]\n");
    let out = run_interactive(
        &ws,
        &["exec", "-p", "ci-state", "--ttl", "1h", "--", "true"],
    );
    assert!(out.success(), "{}", out.stderr);
    let body = body_of(&cf);
    assert_eq!(body["ttlSeconds"], 3600);
    assert_eq!(body["permission"], "object-read-only");
    assert_eq!(body["prefixes"], serde_json::json!(["repo/", "other/"]));
}

#[test]
fn the_command_gets_the_cloudflare_r2_variables_and_a_notice_that_they_cannot_be_revoked() {
    let (_cf, ws) = setup("");
    let out = run_interactive(&ws, &["exec", "-p", "ci-state", "--", "env"]);
    assert!(out.success(), "{}", out.stderr);
    for expected in [
        "CLOUDFLARE_API_TOKEN=FAKE_STATIC_TOKEN_91bc",
        "CLOUDFLARE_R2_ACCESS_KEY_ID=FAKE_TEMP_KEY",
        "CLOUDFLARE_R2_SECRET_ACCESS_KEY=FAKE_TEMP_SECRET",
        "CLOUDFLARE_R2_SESSION_TOKEN=FAKE_TEMP_SESSION",
        "CLOUDFLARE_R2_ENDPOINT=https://abc123.r2.cloudflarestorage.com",
        "CLOUDFLARE_R2_BUCKET=tf-state",
    ] {
        assert!(out.stdout.contains(expected), "missing {expected}");
    }
    assert!(out.stderr.contains("can't be revoked"), "{}", out.stderr);
    assert_no_secrets(
        &out.stderr,
        &["FAKE_TEMP_SECRET", "FAKE_TEMP_SESSION", FAKE_TOKEN],
    );
}

#[test]
fn a_denied_request_explains_the_missing_permission_and_starts_nothing() {
    let (cf, ws) = setup("");
    cf.state.lock().unwrap().deny_r2 = true;
    let marker = ws.path().join("started");
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "ci-state",
            "--",
            "touch",
            &marker.display().to_string(),
        ],
    );
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("R2 permission"), "{}", out.stderr);
    assert!(!marker.exists());
}

#[test]
fn a_profile_without_r2_makes_no_r2_request() {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new("[ci]\ntype = \"token\"\naccount_id = \"abc123\"\n")
        .with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_token("ci", FAKE_TOKEN);
    let out = run_interactive(&ws, &["exec", "-p", "ci", "--", "env"]);
    assert!(out.success());
    assert!(!out.stdout.contains("CLOUDFLARE_R2_"));
    assert!(cloudflare.server.requests().is_empty());
}

#[test]
fn the_token_works_without_a_terminal_too() {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(&config("")).with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    let out = ws
        .cmd()
        .env("CLOUDFLARE_API_TOKEN", FAKE_ENV_TOKEN)
        .args(["exec", "-p", "ci-state", "--", "env"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLOUDFLARE_R2_BUCKET=tf-state"));
}
