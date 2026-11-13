//! `exec` for token profiles.

use expectrl::{session::OsSession, Eof, Expect, Session};

use crate::helpers::*;

const CONFIG: &str = "[ci]\ntype = \"token\"\naccount_id = \"abc123\"\n";

#[test]
fn the_stored_token_is_delivered_with_the_account() {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("ci", FAKE_TOKEN);
    let out = run_interactive(
        &ws,
        &[
            "exec",
            "-p",
            "ci",
            "--",
            "sh",
            "-c",
            "echo \"$CLOUDFLARE_API_TOKEN $CLOUDFLARE_ACCOUNT_ID\"",
        ],
    );
    assert!(out.success(), "{}", out.stderr);
    assert_eq!(out.stdout.trim(), format!("{FAKE_TOKEN} abc123"));
    assert_no_secrets(&out.stderr, &[FAKE_TOKEN]);
}

#[test]
fn an_unavailable_store_fails_login_and_exec_and_leaves_no_plaintext() {
    let ws = Workspace::new(CONFIG).with_env("CF_VAULT_STORE_UNAVAILABLE", "1");
    let mut cmd = ws.std_cmd();
    cmd.args(["login", "-p", "ci"]);
    let mut session: OsSession = Session::spawn(cmd).unwrap();
    session.expect("Cloudflare API token for ci: ").unwrap();
    session.send_line(SENTINEL).unwrap();
    let captured = session.expect(Eof).unwrap();
    let transcript = String::from_utf8_lossy(captured.as_bytes()).into_owned();
    assert!(
        transcript.contains("credential store unavailable"),
        "{transcript}"
    );
    assert!(!transcript.contains(SENTINEL));

    let out = run_interactive(&ws, &["exec", "-p", "ci", "--", "true"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("credential store unavailable"));

    assert!(std::fs::read_dir(ws.store_dir()).unwrap().next().is_none());
    assert_no_secrets(&ws.all_text_except_store(), &[SENTINEL]);
}
