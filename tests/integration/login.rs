//! `login` for api_token profiles: the prompt needs a terminal, so these run in a pty.

use expectrl::{session::OsSession, Eof, Expect, Session};

use crate::helpers::*;

const CONFIG: &str = "[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n";

fn start(ws: &Workspace) -> OsSession {
    let mut cmd = ws.std_cmd();
    cmd.args(["login", "-p", "ci"]);
    Session::spawn(cmd).unwrap()
}

fn finish(mut session: OsSession) -> String {
    let captured = session.expect(Eof).unwrap();
    String::from_utf8_lossy(captured.as_bytes()).into_owned()
}

#[test]
fn the_token_is_asked_for_without_echo_and_stored_as_a_token_session() {
    let ws = Workspace::new(CONFIG);
    let mut session = start(&ws);
    let before = session.expect("Cloudflare API token for ci: ").unwrap();
    let mut transcript = String::from_utf8_lossy(before.before()).into_owned();
    session.send_line(FAKE_TOKEN).unwrap();
    transcript.push_str(&finish(session));
    assert!(
        transcript.contains("Logged in to profile \"ci\""),
        "{transcript}"
    );
    assert!(
        !transcript.contains(FAKE_TOKEN),
        "the token was echoed: {transcript}"
    );
    let stored: serde_json::Value = serde_json::from_str(&ws.stored("ci").unwrap()).unwrap();
    assert_eq!(stored["kind"], "token");
    assert_eq!(stored["access_token"], FAKE_TOKEN);
    assert!(stored.get("refresh_token").is_none());
}

#[test]
fn an_empty_token_is_rejected_and_nothing_is_stored() {
    let ws = Workspace::new(CONFIG);
    let mut session = start(&ws);
    session.expect("Cloudflare API token for ci: ").unwrap();
    session.send_line("").unwrap();
    let transcript = finish(session);
    assert!(transcript.contains("the token is empty"), "{transcript}");
    assert!(ws.stored("ci").is_none());
}

#[test]
fn without_a_terminal_the_prompt_is_refused() {
    let ws = Workspace::new(CONFIG);
    let out = run(&ws, &["login", "-p", "ci"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("interactive terminal"),
        "{}",
        out.stderr
    );
}
