//! Configuration errors seen from the command line (the rules themselves are unit tested).

use crate::helpers::*;

const TOKEN_PROFILE: &str = "[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n";

#[test]
fn every_bad_profile_is_reported_and_no_value_is_echoed() {
    let ws = Workspace::new(&format!(
        "[a]\ntype = \"api_token\"\naccount_id = \"x\"\ntoken = \"{SENTINEL}\"\n\
         [b]\ntype = \"nope\"\naccount_id = \"x\"\n"
    ));
    let out = run(&ws, &["list"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("profile \"a\"") && out.stderr.contains("profile \"b\""));
    assert!(out.stderr.contains("cf-vault login -p a"));
    assert_no_secrets(&out.stderr, &[SENTINEL]);
}

#[test]
fn a_missing_file_names_the_expected_path() {
    let ws = Workspace::new("");
    std::fs::remove_file(ws.config_file()).unwrap();
    let out = run(&ws, &["list"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains(&ws.config_file().display().to_string()));
}

#[test]
fn an_unknown_profile_lists_the_available_ones() {
    let ws = Workspace::new(TOKEN_PROFILE);
    let out = run(&ws, &["logout", "-p", "zzz"]);
    assert_eq!(out.code, Some(1));
    assert!(out.stderr.contains("unknown profile \"zzz\"") && out.stderr.contains("ci"));
}

#[test]
fn no_profile_anywhere_fails_and_lists_the_configured_ones() {
    let ws = Workspace::new(TOKEN_PROFILE);
    let out = run(&ws, &["exec", "--", "true"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("CF_VAULT_PROFILE") && out.stderr.contains("available profiles: ci")
    );
}

#[test]
fn the_profile_flag_is_given_exactly_once() {
    let ws = Workspace::new(TOKEN_PROFILE);
    let out = run(&ws, &["exec", "-p", "ci", "-p", "ci", "--", "true"]);
    assert_eq!(out.code, Some(2), "{}", out.stderr);
}
