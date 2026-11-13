//! Temporary R2 credentials derived from a static API token (no broker).
//!
//! The Cloudflare API takes the parent token as the bearer and the parent's access key id (the
//! token's id) in the body, so the secret half of the parent never leaves this machine. The
//! credentials cannot be revoked; they expire.

use std::time::Duration;

use serde::Deserialize;
use time::OffsetDateTime;

use crate::vault::{
    auth::{redact::Secret, token::http_client},
    cloudflare::credentials::R2Credentials,
    config::R2,
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

/// Derives temporary credentials for the profile's bucket from `token`.
pub fn derive(account_id: &str, token: &Secret, r2: &R2, ttl: Duration) -> Result<R2Credentials> {
    let parent = token_id(account_id, token)?;
    let ttl_seconds = ttl.as_secs().max(1);
    let mut body = serde_json::json!({
        "bucket": r2.bucket,
        "parentAccessKeyId": parent,
        "permission": r2.permission.as_api(),
        "ttlSeconds": ttl_seconds,
    });
    if !r2.prefixes.is_empty() {
        body["prefixes"] = serde_json::json!(r2.prefixes);
    }
    let http = http_client()?;
    let response = http
        .post(format!(
            "{}/accounts/{account_id}/r2/temp-access-credentials",
            api_base()
        ))
        .bearer_auth(token.expose())
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .map_err(|_| Error::R2("could not reach the Cloudflare API".into()))?;
    let status = response.status().as_u16();
    let text = response
        .text()
        .map_err(|_| Error::R2("could not read the Cloudflare API's answer".into()))?;
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
