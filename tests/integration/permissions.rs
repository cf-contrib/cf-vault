//! Nothing credential-bearing outlives the child, and what cf-vault creates is owner-only
//! (Principle V). The lock files' modes are covered in `refresh.rs`.

use crate::helpers::*;

#[test]
fn no_file_with_a_credential_is_left_behind_after_the_command_exits() {
    let ws = Workspace::new("[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n");
    ws.seed_token("ci", SENTINEL);
    let before = ws.all_text_except_store();
    let out = run_interactive(&ws, &["exec", "-p", "ci", "-q", "--", "sh", "-c", "exit 0"]);
    assert!(out.success());
    let after = ws.all_text_except_store();
    assert_no_secrets(&after, &[SENTINEL]);
    // Only lock files (empty) may appear
    assert_eq!(before.len(), after.len());
}

#[test]
fn nothing_is_written_outside_the_workspace_by_a_noninteractive_run() {
    let ws = Workspace::new("[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n")
        .with_env("CF_VAULT_STORE_UNAVAILABLE", "1");
    let out = ws
        .cmd()
        .env("CLOUDFLARE_API_TOKEN", SENTINEL)
        .args(["exec", "-p", "ci", "-q", "--", "true"])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(std::fs::read_dir(ws.store_dir()).unwrap().next().is_none());
    assert!(
        !ws.path().join("state").join("locks").exists(),
        "noninteractive runs persist nothing"
    );
    assert_no_secrets(&ws.all_text_except_store(), &[SENTINEL]);
}
