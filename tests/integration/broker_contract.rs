//! The broker contract (SC-009, FR-014): when `CLOUDFLARE_STS_OPENAPI` points at the broker's
//! compiled `stsv1.yaml`, check that the fields cf-vault sends and reads exist in the schema.
//! Skipped when the variable is unset; the broker repository's own CI is the authority on drift.

#[test]
fn the_fields_cf_vault_uses_exist_in_the_brokers_schema() {
    let Some(path) = std::env::var_os("CLOUDFLARE_STS_OPENAPI") else {
        eprintln!("skipped: CLOUDFLARE_STS_OPENAPI is not set");
        return;
    };
    let schema = std::fs::read_to_string(&path).expect("readable stsv1.yaml");
    // Request fields (form-encoded body of POST /oauth/token) and the revocation request
    for field in [
        "grant_type",
        "subject_token",
        "subject_token_type",
        "scope",
        "audience",
        "ttl",
        "urn:ietf:params:oauth:grant-type:token-exchange",
        "urn:ietf:params:oauth:token-type:id_token",
        "token_type_hint",
    ] {
        assert!(
            schema.contains(field),
            "the schema no longer mentions request field {field}"
        );
    }
    // Response fields cf-vault reads
    for field in [
        "access_token",
        "token_id",
        "account_id",
        "expires_in",
        "bucket",
        "access_key_id",
        "secret_access_key",
        "session_token",
        "prefixes",
        "endpoint",
    ] {
        assert!(
            schema.contains(field),
            "the schema no longer mentions response field {field}"
        );
    }
    // Discovery
    for field in [
        "identity_providers",
        "token_endpoint",
        "revocation_endpoint",
        "client_id",
    ] {
        assert!(
            schema.contains(field),
            "the schema no longer mentions {field}"
        );
    }
    for route in [
        "/oauth/token",
        "/oauth/revoke",
        "/.well-known/oauth-authorization-server",
    ] {
        assert!(schema.contains(route), "the schema no longer has {route}");
    }
}
