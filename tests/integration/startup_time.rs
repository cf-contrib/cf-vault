//! SC-002: with a valid session and no renewal or broker call, `exec` adds under a second.

use std::time::{Duration, Instant};

use crate::helpers::*;

#[test]
fn exec_with_a_valid_session_adds_under_a_second() {
    if std::env::var_os("CF_VAULT_SKIP_TIMING").is_some() {
        eprintln!("skipped: CF_VAULT_SKIP_TIMING is set");
        return;
    }
    let ws = Workspace::new("[ci]\ntype = \"api_token\"\naccount_id = \"abc123\"\n");
    ws.seed_token("ci", FAKE_TOKEN);
    // Warm the filesystem cache, then measure
    assert!(run_interactive(&ws, &["exec", "-p", "ci", "-q", "--", "true"]).success());
    let started = Instant::now();
    assert!(run_interactive(&ws, &["exec", "-p", "ci", "-q", "--", "true"]).success());
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(1), "exec took {elapsed:?}");
}
