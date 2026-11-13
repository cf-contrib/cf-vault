//! R2 credentials from an OAuth session: a short-lived account token is minted as the parent,
//! used, and deleted again.

use crate::helpers::{
    cloudflare::{Cloudflare, MINTED_ID, MINTED_TOKEN},
    *,
};

const ISSUER: &str = "http://127.0.0.1:9";
const OAUTH_ACCESS: &str = "FAKE_OAUTH_ACCESS_5e1";

fn setup(r2_extra: &str) -> (Cloudflare, Workspace) {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(&format!(
        "[personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [personal.oauth2]\nissuer = \"{ISSUER}\"\nclient_id = \"{}\"\n\
         [personal.r2]\nbucket = \"tf-state\"\n{r2_extra}",
        provider::CLIENT_ID
    ))
    .with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_oauth("personal", ISSUER, OAUTH_ACCESS, Some("RT"), 3600, None);
    (cloudflare, ws)
}

fn bearer(request: &mock::Request) -> String {
    request
        .header("authorization")
        .unwrap_or_default()
        .to_string()
}

use crate::helpers::{mock, provider};

#[test]
fn a_token_is_minted_used_as_the_parent_and_deleted() {
    let (cf, ws) = setup("");
    let out = run_interactive(&ws, &["exec", "-p", "personal", "--", "env"]);
    assert!(out.success(), "{}", out.stderr);

    // The OAuth session lists the groups, creates the token, and later deletes it
    let groups = cf.server.hits("/accounts/abc123/tokens/permission_groups");
    assert_eq!(groups.len(), 1);
    assert_eq!(bearer(&groups[0]), format!("Bearer {OAUTH_ACCESS}"));
    let created = cf.server.hits("/accounts/abc123/tokens");
    let create = created.iter().find(|r| r.method == "POST").unwrap();
    assert_eq!(bearer(create), format!("Bearer {OAUTH_ACCESS}"));
    let body: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(body["policies"][0]["permission_groups"][0]["id"], "grp-w");
    assert_eq!(
        body["policies"][0]["resources"]["com.cloudflare.api.account.abc123"],
        "*"
    );
    assert!(body["expires_on"].as_str().unwrap().ends_with('Z'));
    let deletes = cf
        .server
        .hits(&format!("/accounts/abc123/tokens/{MINTED_ID}"));
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].method, "DELETE");
    assert_eq!(bearer(&deletes[0]), format!("Bearer {OAUTH_ACCESS}"));

    // The minted token is the parent of the temporary credentials, and only that
    let temp = cf
        .server
        .hits("/accounts/abc123/r2/temp-access-credentials");
    assert_eq!(temp.len(), 1);
    assert_eq!(bearer(&temp[0]), format!("Bearer {MINTED_TOKEN}"));
    let temp_body: serde_json::Value = serde_json::from_str(&temp[0].body).unwrap();
    assert_eq!(temp_body["parentAccessKeyId"], MINTED_ID);
    assert_eq!(temp_body["bucket"], "tf-state");
    assert_eq!(temp_body["ttlSeconds"], 900);

    // The command gets the OAuth token as the API token and the R2 variables, never the parent
    assert!(out
        .stdout
        .contains(&format!("CLOUDFLARE_API_TOKEN={OAUTH_ACCESS}")));
    for expected in [
        "CLOUDFLARE_R2_ACCESS_KEY_ID=FAKE_TEMP_KEY",
        "CLOUDFLARE_R2_SECRET_ACCESS_KEY=FAKE_TEMP_SECRET",
        "CLOUDFLARE_R2_SESSION_TOKEN=FAKE_TEMP_SESSION",
        "CLOUDFLARE_R2_BUCKET=tf-state",
    ] {
        assert!(out.stdout.contains(expected), "missing {expected}");
    }
    assert_no_secrets(&out.stdout, &[MINTED_TOKEN]);
    assert_no_secrets(
        &out.stderr,
        &[MINTED_TOKEN, OAUTH_ACCESS, "FAKE_TEMP_SECRET"],
    );
    assert!(out.stderr.contains("can't be revoked"));
}

#[test]
fn read_only_credentials_use_the_read_permission() {
    let (cf, ws) = setup("permission = \"object-read-only\"\n");
    let out = run_interactive(&ws, &["exec", "-p", "personal", "-q", "--", "true"]);
    assert!(out.success(), "{}", out.stderr);
    let created = cf.server.hits("/accounts/abc123/tokens");
    let create = created.iter().find(|r| r.method == "POST").unwrap();
    let body: serde_json::Value = serde_json::from_str(&create.body).unwrap();
    assert_eq!(body["policies"][0]["permission_groups"][0]["id"], "grp-r");
}

#[test]
fn a_fresh_token_is_retried_until_the_api_accepts_it() {
    let (cf, ws) = setup("");
    cf.state.lock().unwrap().propagation_failures = 2;
    let out = run_interactive(&ws, &["exec", "-p", "personal", "-q", "--", "true"]);
    assert!(out.success(), "{}", out.stderr);
    assert_eq!(
        cf.server
            .hits("/accounts/abc123/r2/temp-access-credentials")
            .len(),
        3
    );
    assert_eq!(
        cf.server
            .hits(&format!("/accounts/abc123/tokens/{MINTED_ID}"))
            .len(),
        1
    );
}

#[test]
fn a_failure_still_deletes_the_token_and_starts_nothing() {
    let (cf, ws) = setup("");
    cf.state.lock().unwrap().deny_r2 = true;
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
    assert!(out.stderr.contains("R2 permission"), "{}", out.stderr);
    assert!(!marker.exists());
    assert_eq!(
        cf.server
            .hits(&format!("/accounts/abc123/tokens/{MINTED_ID}"))
            .len(),
        1
    );
    assert_no_secrets(&out.stderr, &[MINTED_TOKEN, OAUTH_ACCESS]);
}

#[test]
fn a_refused_mint_says_which_scope_the_session_needs() {
    let (cf, ws) = setup("");
    cf.state.lock().unwrap().deny_mint = true;
    let out = run_interactive(&ws, &["exec", "-p", "personal", "--", "true"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("account-api-tokens.write"),
        "{}",
        out.stderr
    );
    assert!(cf
        .server
        .hits("/accounts/abc123/r2/temp-access-credentials")
        .is_empty());
}

#[test]
fn it_works_without_a_terminal_with_a_supplied_token() {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(
        "[personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n[personal.r2]\nbucket = \"tf-state\"\n",
    )
    .with_env("CF_VAULT_API_URL", &cloudflare.api_url())
    .with_env("CF_VAULT_STORE_UNAVAILABLE", "1");
    let out = ws
        .cmd()
        .env("CLOUDFLARE_API_TOKEN", FAKE_ENV_TOKEN)
        .args(["exec", "-p", "personal", "--", "env"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("CLOUDFLARE_R2_BUCKET=tf-state"));
    assert!(stdout.contains(&format!("CLOUDFLARE_API_TOKEN={FAKE_ENV_TOKEN}")));
}
