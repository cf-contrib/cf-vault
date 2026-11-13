//! `list`: profiles and session states, never a secret.

use crate::helpers::*;

const CONFIG: &str = "[tokened]\ntype = \"token\"\naccount_id = \"a1\"\n\
                      [empty-token]\ntype = \"token\"\naccount_id = \"a2\"\n\
                      [fresh]\ntype = \"oauth2\"\naccount_id = \"a3\"\n\
                      [fresh.oauth2]\nissuer = \"http://127.0.0.1:9\"\nclient_id = \"fake-client\"\n\
                      [stale]\ntype = \"oauth2\"\naccount_id = \"a4\"\n\
                      [stale.oauth2]\nissuer = \"http://127.0.0.1:9\"\nclient_id = \"fake-client\"\n\
                      [renewable]\ntype = \"oauth2\"\naccount_id = \"a5\"\n\
                      [renewable.oauth2]\nissuer = \"http://127.0.0.1:9\"\nclient_id = \"fake-client\"\n\
                      [absent]\ntype = \"oauth2\"\naccount_id = \"a6\"\n\
                      [absent.oauth2.exchange]\nurl = \"https://broker.example\"\nprofile = \"p\"\n";

fn seeded() -> Workspace {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("tokened", FAKE_TOKEN);
    ws.seed_oauth(
        "fresh",
        "http://127.0.0.1:9",
        "FRESH_AT",
        Some("FRESH_RT"),
        3600,
        None,
    );
    ws.seed_oauth("stale", "http://127.0.0.1:9", "STALE_AT", None, -10, None);
    ws.seed_oauth(
        "renewable",
        "http://127.0.0.1:9",
        "R_AT",
        Some("R_RT"),
        -10,
        None,
    );
    ws
}

#[test]
fn every_profile_is_shown_with_its_state_and_no_secret() {
    let ws = seeded();
    let out = run(&ws, &["list"]);
    assert!(out.success(), "{}", out.stderr);
    let row = |name: &str| {
        out.stdout
            .lines()
            .find(|l| l.starts_with(name) && l.split_whitespace().next() == Some(name))
            .unwrap_or_else(|| panic!("no row for {name} in {}", out.stdout))
            .to_string()
    };
    assert!(row("tokened").ends_with("static token"));
    assert!(row("empty-token").ends_with("not signed in"));
    assert!(row("fresh").ends_with("signed in"));
    assert!(row("stale").ends_with("expired"));
    assert!(row("renewable").ends_with("signed in"));
    assert!(row("absent").contains("yes") && row("absent").ends_with("not signed in"));
    assert!(out.stdout.starts_with("PROFILE"));
    assert_no_secrets(
        &format!("{}{}", out.stdout, out.stderr),
        &[
            FAKE_TOKEN, "FRESH_AT", "FRESH_RT", "STALE_AT", "R_AT", "R_RT",
        ],
    );
}

#[test]
fn the_json_form_is_stable() {
    let ws = seeded();
    let out = run(&ws, &["list", "--json"]);
    assert!(out.success());
    let rows: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let first = &rows[0];
    assert_eq!(
        first
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        ["account_id", "exchange", "profile", "state", "type"]
    );
    assert_eq!(first["profile"], "tokened");
    assert_eq!(first["type"], "token");
    assert_eq!(first["exchange"], false);
    assert_eq!(first["state"], "static token");
    let by_name = |n: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["profile"] == n)
            .unwrap()
            .clone()
    };
    assert_eq!(by_name("absent")["exchange"], true);
    assert_no_secrets(&out.stdout, &[FAKE_TOKEN, "FRESH_AT", "FRESH_RT"]);
}
