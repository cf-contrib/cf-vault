//! Temporary R2 credentials derived without a broker, from an API token or, with a short-lived
//! token minted for the purpose, from an OAuth session.
//!
//! The Cloudflare API takes the parent token as the bearer and the parent's access key id (the
//! token's id) in the body, so the secret half of the parent never leaves this machine. The
//! credentials cannot be revoked; they expire.

use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

use crate::vault::{
    auth::{redact::Secret, token::http_client},
    cloudflare::creds::R2Credentials,
    config::{Permission, R2},
    Error, Result,
};

/// Default lifetime of directly derived R2 credentials.
pub const DEFAULT_TTL: Duration = Duration::from_secs(900);

fn api_base() -> String {
    #[cfg(feature = "test-store")]
    if let Ok(url) = std::env::var("CF_VAULT_API_URL") {
        return url.trim_end_matches('/').to_string();
    }
    "https://api.cloudflare.com/client/v4".to_string()
}

#[derive(Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    success: bool,
    result: Option<T>,
    #[serde(default)]
    errors: Vec<ApiError>,
}

#[derive(Deserialize)]
struct ApiError {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

#[derive(Deserialize)]
struct Verified {
    id: String,
}

#[derive(Deserialize)]
struct Temporary {
    #[serde(rename = "accessKeyId")]
    access_key_id: String,
    #[serde(rename = "secretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "sessionToken")]
    session_token: String,
}

fn failure(context: &str, status: u16, body: &str) -> Error {
    let errors = serde_json::from_str::<Envelope<serde_json::Value>>(body)
        .map(|e| e.errors)
        .unwrap_or_default();
    if errors.iter().any(|e| e.code == 10000) {
        return Error::R2(format!(
            "Cloudflare refused the request ({context}); the token needs an R2 permission \
             (for example Workers R2 Storage Write)"
        ));
    }
    let detail = errors
        .first()
        .map(|e| {
            let message: String = e.message.chars().take(200).collect();
            format!(": {message}")
        })
        .unwrap_or_default();
    Error::R2(format!("{context} failed (HTTP {status}{detail})"))
}

/// Reads the id of `token` from Cloudflare's token-verify endpoint: the account-owned form first,
/// then the user form.
fn token_id(account_id: &str, token: &Secret) -> Result<String> {
    let http = http_client()?;
    let base = api_base();
    let mut last = None;
    for path in [
        format!("{base}/accounts/{account_id}/tokens/verify"),
        format!("{base}/user/tokens/verify"),
    ] {
        let response = http
            .get(&path)
            .bearer_auth(token.expose())
            .send()
            .map_err(|_| Error::R2("could not reach the Cloudflare API".into()))?;
        let status = response.status().as_u16();
        let body = response
            .text()
            .map_err(|_| Error::R2("could not read the Cloudflare API's answer".into()))?;
        if (200..300).contains(&status) {
            if let Ok(envelope) = serde_json::from_str::<Envelope<Verified>>(&body) {
                if let (true, Some(result)) = (envelope.success, envelope.result) {
                    return Ok(result.id);
                }
            }
        }
        last = Some(failure("verifying the API token", status, &body));
    }
    Err(last.expect("two attempts were made"))
}

fn propagation_delay() -> Duration {
    #[cfg(feature = "test-store")]
    if let Some(ms) = std::env::var("CF_VAULT_RETRY_DELAY_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    Duration::from_secs(2)
}

/// How many times a freshly minted token is tried before giving up: a new token needs a few
/// seconds before the API accepts it.
const PROPAGATION_ATTEMPTS: u32 = 8;

#[derive(Deserialize)]
struct PermissionGroup {
    id: String,
    name: String,
}

#[derive(Deserialize)]
struct Minted {
    id: String,
    value: String,
}

/// Sends a JSON request and returns the status and body text.
fn send(
    token: &Secret,
    method: oauth2::reqwest::Method,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<(u16, String)> {
    let http = http_client()?;
    let mut request = http
        .request(method, format!("{}{path}", api_base()))
        .bearer_auth(token.expose());
    if let Some(body) = body {
        request = request
            .header("Content-Type", "application/json")
            .body(body.to_string());
    }
    let response = request
        .send()
        .map_err(|_| Error::R2("could not reach the Cloudflare API".into()))?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .map_err(|_| Error::R2("could not read the Cloudflare API's answer".into()))?;
    Ok((status, text))
}

/// Derives temporary credentials for the profile's bucket from an OAuth session (or any token
/// that may create account API tokens): it mints a short-lived account token with the R2
/// permission the credentials need, derives the credentials from it, and deletes it again.
/// The session needs the `account-api-tokens.write` scope and the R2 permission it delegates
/// (`workers-r2.write`, or `workers-r2.read` for read-only credentials).
pub fn derive_minting(
    account_id: &str,
    token: &Secret,
    r2: &R2,
    ttl: Duration,
) -> Result<R2Credentials> {
    use oauth2::reqwest::Method;

    let wanted = match r2.permission {
        Permission::ObjectReadWrite => "Workers R2 Storage Write",
        Permission::ObjectReadOnly => "Workers R2 Storage Read",
    };
    let (status, text) = send(
        token,
        Method::GET,
        &format!("/accounts/{account_id}/tokens/permission_groups"),
        None,
    )?;
    if !(200..300).contains(&status) {
        return Err(failure(
            "listing the token permission groups",
            status,
            &text,
        ));
    }
    let groups: Envelope<Vec<PermissionGroup>> = serde_json::from_str(&text)
        .map_err(|_| Error::R2("the Cloudflare API returned an unexpected response".into()))?;
    let group = groups
        .result
        .unwrap_or_default()
        .into_iter()
        .find(|g| g.name == wanted)
        .ok_or_else(|| {
            Error::R2(format!(
                "Cloudflare has no permission group named \"{wanted}\""
            ))
        })?;

    let ttl_seconds = ttl.as_secs().max(1);
    let expires_on = (OffsetDateTime::now_utc()
        + time::Duration::seconds(ttl_seconds as i64 + 300))
    .replace_nanosecond(0)
    .ok()
    .and_then(|t| {
        t.format(&time::format_description::well_known::Rfc3339)
            .ok()
    })
    .unwrap_or_default();
    let (status, text) = send(
        token,
        Method::POST,
        &format!("/accounts/{account_id}/tokens"),
        Some(serde_json::json!({
            "name": "cf-vault temporary R2 parent",
            "expires_on": expires_on,
            "policies": [{
                "effect": "allow",
                "resources": { format!("com.cloudflare.api.account.{account_id}"): "*" },
                "permission_groups": [{ "id": group.id }],
            }],
        })),
    )?;
    if !(200..300).contains(&status) {
        return Err(failure(
            "creating the temporary API token (the session needs the account-api-tokens.write scope)",
            status,
            &text,
        ));
    }
    let minted: Minted = serde_json::from_str::<Envelope<Minted>>(&text)
        .ok()
        .and_then(|e| e.result)
        .ok_or_else(|| Error::R2("the Cloudflare API returned an unexpected response".into()))?;
    let parent = Secret::new(minted.value);

    let derived = (|| {
        for attempt in 1..=PROPAGATION_ATTEMPTS {
            match derive_from_parent(account_id, &parent, &minted.id, r2, ttl_seconds) {
                // A token this new is refused for a moment
                Err(Error::R2(m)) if m.contains("HTTP 401") && attempt < PROPAGATION_ATTEMPTS => {
                    std::thread::sleep(propagation_delay());
                }
                other => return other,
            }
        }
        unreachable!("the last attempt returns")
    })();

    // Whatever happened, the temporary token goes
    let deleted = send(
        token,
        Method::DELETE,
        &format!("/accounts/{account_id}/tokens/{}", minted.id),
        None,
    );
    if !matches!(deleted, Ok((status, _)) if (200..300).contains(&status)) {
        eprintln!(
            "cf-vault: warning: the temporary API token \"cf-vault temporary R2 parent\" was not \
             deleted; it expires by itself"
        );
    }
    derived
}

/// Derives temporary credentials for the profile's bucket from `token`.
pub fn derive(account_id: &str, token: &Secret, r2: &R2, ttl: Duration) -> Result<R2Credentials> {
    let parent = token_id(account_id, token)?;
    derive_from_parent(account_id, token, &parent, r2, ttl.as_secs().max(1))
}

/// Creates the temporary credentials, with `token` as the bearer and `parent` as the parent's
/// access key id.
fn derive_from_parent(
    account_id: &str,
    token: &Secret,
    parent: &str,
    r2: &R2,
    ttl_seconds: u64,
) -> Result<R2Credentials> {
    let mut body = serde_json::json!({
        "bucket": r2.bucket,
        "parentAccessKeyId": parent,
        "permission": r2.permission.as_api(),
        "ttlSeconds": ttl_seconds,
    });
    if !r2.prefixes.is_empty() {
        body["prefixes"] = serde_json::json!(r2.prefixes);
    }
    let (status, text) = send(
        token,
        oauth2::reqwest::Method::POST,
        &format!("/accounts/{account_id}/r2/temp-access-credentials"),
        Some(body),
    )?;
    if !(200..300).contains(&status) {
        return Err(failure("creating the temporary credentials", status, &text));
    }
    let envelope: Envelope<Temporary> = serde_json::from_str(&text)
        .map_err(|_| Error::R2("the Cloudflare API returned an unexpected response".into()))?;
    let Some(temporary) = envelope.result.filter(|_| envelope.success) else {
        return Err(failure("creating the temporary credentials", status, &text));
    };
    Ok(R2Credentials {
        access_key_id: Secret::new(temporary.access_key_id),
        secret_access_key: Secret::new(temporary.secret_access_key),
        session_token: Secret::new(temporary.session_token),
        endpoint: format!("https://{account_id}.r2.cloudflarestorage.com"),
        bucket: r2.bucket.clone(),
        prefixes: r2.prefixes.clone(),
        expires_at: Some(OffsetDateTime::now_utc() + time::Duration::seconds(ttl_seconds as i64)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_10000_explains_the_missing_permission() {
        let body =
            r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}"#;
        let message = failure("creating", 403, body).to_string();
        assert!(message.contains("R2 permission"));
        let message = failure("creating", 500, "not json").to_string();
        assert!(message.contains("HTTP 500"));
    }
}
