//! `exec`: credentials in the child's environment only, exit statuses, signals and profile
//! selection. These run with standard input treated as a terminal (see `Workspace::interactive`).

use std::io::{BufRead, BufReader};
use std::process::Stdio;

use crate::helpers::*;

const ISSUER: &str = "http://127.0.0.1:9";

fn workspace() -> Workspace {
    let ws = Workspace::new(&oauth_config(ISSUER, free_port()));
    ws.seed_oauth(
        "personal",
        ISSUER,
        "FAKE_ACCESS_X",
        Some("FAKE_REFRESH_X"),
        3600,
        None,
    );
    ws
}

#[test]
fn the_command_gets_the_token_and_account_and_its_exit_status_comes_back() {
    let ws = workspace();
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "--",
            "sh",
            "-c",
            "echo \"$CLOUDFLARE_API_TOKEN:$CLOUDFLARE_ACCOUNT_ID\"; exit 7",
        ],
    );
    assert_eq!(out.code, Some(7), "{}", out.stderr);
    assert_eq!(out.stdout.trim(), "FAKE_ACCESS_X:abc123");
    assert!(out.stderr.contains("cf-vault: profile personal"));
    assert_no_secrets(&out.stderr, &["FAKE_ACCESS_X", "FAKE_REFRESH_X"]);
    // The parent environment is not touched
    assert!(std::env::var("CLOUDFLARE_API_TOKEN").is_err());
}

#[test]
fn standard_input_output_and_error_are_inherited() {
    let ws = workspace();
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "-q",
            "--",
            "sh",
            "-c",
            "echo out; echo err >&2",
        ],
    );
    assert!(out.success());
    assert_eq!(out.stdout, "out\n");
    assert_eq!(out.stderr, "err\n");
}

#[test]
fn the_profile_comes_from_the_flag_or_the_environment_and_the_flag_wins() {
    let ws = workspace();
    let mut by_env = ws.interactive();
    by_env.env("CF_VAULT_PROFILE", "personal");
    let out = by_env
        .args([
            "exec",
            "-q",
            "--",
            "sh",
            "-c",
            "echo $CLOUDFLARE_ACCOUNT_ID",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "abc123");

    let mut both = ws.interactive();
    both.env("CF_VAULT_PROFILE", "does-not-exist");
    let out = both
        .args(["exec", "-p", "personal", "-q", "--", "true"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "the flag must win over the environment"
    );
}

#[test]
fn a_missing_command_gives_127_and_a_signal_death_gives_128_plus_n() {
    let ws = workspace();
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "-q",
            "--",
            "definitely-not-a-command",
        ],
    );
    assert_eq!(out.code, Some(127), "{}", out.stderr);
    assert!(out.stderr.contains("command not found"));
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "-q",
            "--",
            "sh",
            "-c",
            "kill -9 $$",
        ],
    );
    assert_eq!(out.code, Some(137));
}

#[test]
fn sigterm_is_forwarded_to_the_command() {
    let ws = workspace();
    let mut cmd = ws.std_cmd();
    cmd.env("CF_VAULT_FORCE_INTERACTIVE", "1")
        .args([
            "exec",
            "-p",
            "personal",
            "-q",
            "--",
            "sh",
            "-c",
            "trap 'echo got-term; exit 3' TERM; echo ready; while :; do sleep 0.1; done",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "ready");
    let status = std::process::Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert_eq!(lines.next().unwrap().unwrap(), "got-term");
    assert_eq!(child.wait().unwrap().code(), Some(3));
}

#[test]
fn a_signed_out_profile_does_not_start_the_command() {
    let ws = workspace();
    std::fs::remove_file(ws.store_dir().join("personal.json")).unwrap();
    let marker = ws.path().join("started");
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "personal",
            "--",
            "sh",
            "-c",
            &format!("touch {}", marker.display()),
        ],
    );
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("cf-vault login -p personal"));
    assert!(!marker.exists());
}
