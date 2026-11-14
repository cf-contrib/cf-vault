//! Sentinel secrets through login, exec, exchange, R2 and logout: stdout, stderr and every
//! plain file (the credential store aside) stay clean (SC-004, SC-005).

use crate::helpers::{broker::Broker, cloudflare::Cloudflare, provider::Provider, *};

#[test]
fn broker_and_r2_secrets_never_reach_output_or_plain_files() {
    let provider = Provider::start();
    let broker = Broker::start(
        vec![("idp".into(), provider.url(), provider::CLIENT_ID.into())],
        "abc123",
    );
    broker.state.lock().unwrap().with_bucket = true;
    let cloudflare = Cloudflare::start();
    let ws = Workspace::new(&format!(
        "[production]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [production.oauth2]\nredirect_port = {}\n\
         [production.oauth2.exchange]\nissuer = \"{}\"\nscopes = [\"p\"]\n\
         [ci-state]\ntype = \"api_token\"\naccount_id = \"abc123\"\n[ci-state.r2]\nbucket = \"tf-state\"\n",
        free_port(),
        broker.url()
    ))
    .with_env("CF_VAULT_API_URL", &cloudflare.api_url());
    ws.seed_token("ci-state", SENTINEL);

    let mut transcript = String::new();
    let mut add = |out: &Finished| {
        transcript.push_str(&out.stdout);
        transcript.push_str(&out.stderr);
    };
    add(&login(&ws, "production"));
    // The commands print nothing secret themselves, so only cf-vault's own output is scanned
    for profile in ["production", "ci-state"] {
        add(&run_interactive(
            &ws,
            &["exec", "-p", profile, "-v", "--", "true"],
        ));
    }
    add(&run(&ws, &["list"]));
    add(&run(&ws, &["logout", "-p", "production", "-v"]));

    let stored_id = "FAKE_ACCESS_1";
    assert_no_secrets(
        &transcript,
        &[
            SENTINEL,
            "FAKE_BROKER_TOKEN",
            "FAKE_R2_SECRET",
            "FAKE_R2_SESSION",
            "FAKE_TEMP_SECRET",
            "FAKE_TEMP_SESSION",
            stored_id,
            "FAKE_REFRESH_1",
        ],
    );
    assert_no_secrets(
        &ws.all_text_except_store(),
        &[
            SENTINEL,
            "FAKE_BROKER_TOKEN",
            "FAKE_TEMP_SECRET",
            stored_id,
            "FAKE_REFRESH_1",
        ],
    );
}
