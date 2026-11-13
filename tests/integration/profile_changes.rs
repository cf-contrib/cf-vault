//! The inherited-token override and the removal of stale variables.

use expectrl::{session::OsSession, Eof, Expect, Session};

use crate::helpers::*;

const CONFIG: &str = "[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n";

fn in_pty(ws: &Workspace, env: &[(&str, &str)], args: &[&str]) -> String {
    let mut cmd = ws.std_cmd();
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.args(args);
    let mut session: OsSession = Session::spawn(cmd).unwrap();
    let captured = session.expect(Eof).unwrap();
    String::from_utf8_lossy(captured.as_bytes()).into_owned()
}

#[test]
fn in_a_terminal_an_inherited_token_is_replaced_with_exactly_one_notice() {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("ci", FAKE_TOKEN);
    let output = in_pty(
        &ws,
        &[("CLOUDFLARE_API_TOKEN", "OLD_INHERITED_TOKEN")],
        &[
            "exec",
            "-p",
            "ci",
            "--",
            "sh",
            "-c",
            "echo token=$CLOUDFLARE_API_TOKEN",
        ],
    );
    let notice =
        "cf-vault: overriding CLOUDFLARE_API_TOKEN from the environment with profile \"ci\"";
    assert_eq!(output.matches(notice).count(), 1, "{output}");
    assert!(output.contains(&format!("token={FAKE_TOKEN}")), "{output}");
    assert!(
        !output.contains("OLD_INHERITED_TOKEN"),
        "the notice must not show the value: {output}"
    );
}

#[test]
fn without_a_token_in_the_environment_there_is_no_notice() {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("ci", FAKE_TOKEN);
    let output = in_pty(&ws, &[], &["exec", "-p", "ci", "--", "true"]);
    assert!(!output.contains("overriding"), "{output}");
}

#[test]
fn stale_r2_variables_are_removed_when_the_profile_grants_none() {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("ci", FAKE_TOKEN);
    let out = ws
        .interactive()
        .env("CLOUDFLARE_R2_BUCKET", "stale")
        .env("CLOUDFLARE_R2_SESSION_TOKEN", "stale-session")
        .args(["exec", "-p", "ci", "-q", "--", "env"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(!stdout.contains("CLOUDFLARE_R2_"), "{stdout}");
}
