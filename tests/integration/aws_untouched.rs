//! `AWS_*` variables are never set, changed or removed, and direct R2 needs a static token.

use crate::helpers::{cloudflare::Cloudflare, *};

fn aws_lines(ws: &Workspace, profile: &str) -> String {
    let out = ws
        .interactive()
        .env("AWS_ACCESS_KEY_ID", "preset-key")
        .env("AWS_SECRET_ACCESS_KEY", "preset-secret")
        .env("AWS_SESSION_TOKEN", "preset-session")
        .args([
            "exec",
            "-p",
            profile,
            "-q",
            "--",
            "sh",
            "-c",
            "env | grep '^AWS_' | sort",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

const PRESET: &str =
    "AWS_ACCESS_KEY_ID=preset-key\nAWS_SECRET_ACCESS_KEY=preset-secret\nAWS_SESSION_TOKEN=preset-session\n";

#[test]
fn preset_aws_variables_reach_the_command_unchanged_with_and_without_r2() {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(
        "[plain]\ntype = \"token\"\naccount_id = \"abc123\"\n\
         [withr2]\ntype = \"token\"\naccount_id = \"abc123\"\n[withr2.r2]\nbucket = \"tf-state\"\n",
    )
    .with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_token("plain", FAKE_TOKEN);
    ws.seed_token("withr2", FAKE_TOKEN);
    assert_eq!(aws_lines(&ws, "plain"), PRESET);
    assert_eq!(aws_lines(&ws, "withr2"), PRESET);
}

#[test]
fn no_aws_variable_is_added_when_none_was_set() {
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(
        "[withr2]\ntype = \"token\"\naccount_id = \"abc123\"\n[withr2.r2]\nbucket = \"tf-state\"\n",
    )
    .with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_token("withr2", FAKE_TOKEN);
    let out = run_interactive(&ws, &["exec", "-p", "withr2", "-q", "--", "env"]);
    assert!(out.success());
    assert!(!out.stdout.contains("AWS_"), "{}", out.stdout);
}

#[test]
fn an_oauth_profile_with_an_r2_bucket_and_no_broker_is_rejected_at_load() {
    let ws = Workspace::new(
        "[a]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n[a.r2]\nbucket = \"tf-state\"\n",
    );
    let out = run(&ws, &["list"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("only supported for type = \"token\""),
        "{}",
        out.stderr
    );
}
