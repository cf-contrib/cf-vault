//! The credential store: a missing keychain fails clearly, and a session of the wrong kind
//! counts as not signed in.

use crate::helpers::*;

const CONFIG: &str = "[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n\
                      [personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
                      [personal.oauth2]\nissuer = \"http://127.0.0.1:9\"\nclient_id = \"c\"\n";

#[test]
fn an_unavailable_store_fails_clearly_and_writes_nothing() {
    let ws = Workspace::new(CONFIG).with_env("CF_VAULT_STORE_UNAVAILABLE", "1");
    for args in [["list"].as_slice(), ["logout", "-p", "ci"].as_slice()] {
        let out = run(&ws, args);
        assert_eq!(out.code, Some(1), "{}", out.stderr);
        assert!(out.stderr.contains("credential store unavailable"));
    }
    // Nothing was written anywhere, in the store or elsewhere
    assert!(std::fs::read_dir(ws.store_dir()).unwrap().next().is_none());
}

#[test]
fn a_session_of_the_wrong_kind_counts_as_not_signed_in() {
    let ws = Workspace::new(CONFIG);
    ws.seed_token("personal", FAKE_TOKEN);
    let out = run(&ws, &["list", "--json"]);
    assert!(out.success(), "{}", out.stderr);
    let rows: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let state = |name: &str| {
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["profile"] == name)
            .unwrap()["state"]
            .clone()
    };
    assert_eq!(state("personal"), "not signed in");
    assert_eq!(state("ci"), "not signed in");
}
