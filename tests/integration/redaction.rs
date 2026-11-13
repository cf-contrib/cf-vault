//! No secret value reaches standard output, standard error, `-v` output or a plain file.

use crate::helpers::{provider::Provider, *};

#[test]
fn a_whole_session_leaks_no_token_anywhere_but_the_store() {
    let provider = Provider::start();
    let ws = Workspace::new(&oauth_config(&provider.url(), free_port()));
    let mut transcript = String::new();

    let login = login(&ws, "personal");
    assert!(login.success(), "{}", login.stderr);
    transcript.push_str(&login.stdout);
    transcript.push_str(&login.stderr);

    let stored: serde_json::Value = serde_json::from_str(&ws.stored("personal").unwrap()).unwrap();
    let access = stored["access_token"].as_str().unwrap().to_string();
    let refresh = stored["refresh_token"].as_str().unwrap().to_string();
    let id_token = stored["id_token"].as_str().unwrap().to_string();

    for args in [
        vec!["exec", "-p", "personal", "-v", "--", "true"],
        vec!["exec", "-p", "personal", "--", "sh", "-c", "exit 4"],
        vec!["list"],
        vec!["list", "--json"],
    ] {
        let out = run_interactive(&ws, &args);
        transcript.push_str(&out.stdout);
        transcript.push_str(&out.stderr);
    }
    let out = run(&ws, &["logout", "-p", "personal", "-v"]);
    transcript.push_str(&out.stdout);
    transcript.push_str(&out.stderr);

    assert_no_secrets(&transcript, &[&access, &refresh, &id_token]);
    assert_no_secrets(&ws.all_text_except_store(), &[&access, &refresh, &id_token]);
}

#[test]
fn error_paths_never_echo_a_supplied_token() {
    let ws = Workspace::new("[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n");
    // A token that is supplied but the profile is unknown: nothing about the value may show
    let out = ws
        .interactive()
        .env("CLOUDFLARE_API_TOKEN", SENTINEL)
        .args(["exec", "-p", "zzz", "--", "true"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_no_secrets(&String::from_utf8_lossy(&out.stderr), &[SENTINEL]);
}
