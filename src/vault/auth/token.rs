//! Talking to an identity provider: OIDC discovery, the token endpoint, refresh and revocation.
//!
//! Adapted from nix-vault's token module (MIT). Redirects are disabled and every request has a
//! timeout. Response bodies are never echoed: errors carry only the OAuth error code and a
//! description with known secrets removed.

use std::time::Duration;

use oauth2::reqwest::blocking::Client as HttpClient;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::vault::{
    auth::redact::{redact, Secret},
    config::endpoint_allowed,
    Error, Result,
};

/// Tokens obtained from a provider.
#[derive(Debug)]
pub struct TokenSet {
    /// Access token.
    pub access_token: Secret,
    /// OIDC ID token, when issued.
    pub id_token: Option<Secret>,
    /// Refresh token, when issued.
    pub refresh_token: Option<Secret>,
    /// Lifetime of the access token, when reported.
    pub expires_in: Option<Duration>,
}

/// The endpoints of an identity provider, from its OIDC discovery document.
#[derive(Clone, Debug)]
pub struct Provider {
    /// The issuer, without a trailing slash.
    pub issuer: String,
    /// Where the browser goes to sign in.
    pub authorization_endpoint: String,
    /// Where codes and refresh tokens are exchanged.
    pub token_endpoint: String,
    /// Where tokens are revoked, when offered.
    pub revocation_endpoint: Option<String>,
    /// Scopes the provider says it supports (empty when it does not say).
    pub scopes_supported: Vec<String>,
}

/// Builds the HTTP client: no redirects (they could send credentials elsewhere) and timeouts.
pub fn http_client() -> Result<HttpClient> {
    HttpClient::builder()
        .redirect(oauth2::reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| Error::Auth("cannot create the HTTP client".into()))
}

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    #[serde(default)]
    revocation_endpoint: Option<String>,
    #[serde(default)]
    scopes_supported: Vec<String>,
}

/// Reads the provider's OIDC discovery document (one `GET`). The issuer in the document must be
/// the one asked for, and every endpoint must be `https` (or loopback `http`).
pub fn discover(issuer: &str) -> Result<Provider> {
    let issuer = issuer.trim_end_matches('/');
    let url = format!("{issuer}/.well-known/openid-configuration");
    let http = http_client()?;
    let response = http
        .get(&url)
        .send()
        .map_err(|_| Error::Auth(format!("could not reach the identity provider at {issuer}")))?;
    if !response.status().is_success() {
        return Err(Error::Auth(format!(
            "the identity provider at {issuer} has no discovery document (HTTP {})",
            response.status().as_u16()
        )));
    }
    let text = response
        .text()
        .map_err(|_| Error::Auth("could not read the discovery document".into()))?;
    let doc: Discovery = serde_json::from_str(&text)
        .map_err(|_| Error::Auth(format!("the discovery document of {issuer} is not valid")))?;
    if doc.issuer.trim_end_matches('/') != issuer {
        return Err(Error::Auth(format!(
            "the discovery document names a different issuer than {issuer}"
        )));
    }
    for endpoint in [&doc.authorization_endpoint, &doc.token_endpoint]
        .into_iter()
        .chain(doc.revocation_endpoint.as_ref())
    {
        if !endpoint_allowed(endpoint) {
            return Err(Error::Auth(format!(
                "the identity provider at {issuer} names an endpoint that is not https"
            )));
        }
    }
    Ok(Provider {
        issuer: issuer.to_string(),
        authorization_endpoint: doc.authorization_endpoint,
        token_endpoint: doc.token_endpoint,
        revocation_endpoint: doc.revocation_endpoint,
        scopes_supported: doc.scopes_supported,
    })
}

#[derive(Deserialize)]
struct TokenBody {
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// Turns an error response into a short message without bodies or secrets.
fn describe(status: u16, body: &str, secrets: &[&str]) -> String {
    if let Ok(parsed) = serde_json::from_str::<TokenBody>(body) {
        if let Some(error) = parsed.error {
            let error: String = error
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(60)
                .collect();
            let detail = parsed
                .error_description
                .map(|d| redact(&d, secrets).chars().take(200).collect::<String>())
                .map(|d| format!(": {d}"))
                .unwrap_or_default();
            return format!("the provider answered {error}{detail}");
        }
    }
    format!("the token endpoint answered HTTP {status}")
}

/// Posts a form to the token endpoint and returns the tokens.
fn request_tokens(
    endpoint: &str,
    form: &[(&str, &str)],
    secrets: &[&str],
) -> std::result::Result<TokenSet, String> {
    let http = http_client().map_err(|e| e.to_string())?;
    let response = http
        .post(endpoint)
        .form(form)
        .send()
        .map_err(|_| "could not reach the token endpoint".to_string())?;
    let status = response.status().as_u16();
    let body = response
        .text()
        .map_err(|_| "could not read the token endpoint's answer".to_string())?;
    if !(200..300).contains(&status) {
        return Err(describe(status, &body, secrets));
    }
    let parsed: TokenBody = serde_json::from_str(&body)
        .map_err(|_| "the token endpoint returned an unexpected response".to_string())?;
    let access_token = parsed
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| "the token endpoint returned no access token".to_string())?;
    Ok(TokenSet {
        access_token: Secret::new(access_token),
        id_token: parsed.id_token.filter(|t| !t.is_empty()).map(Secret::new),
        refresh_token: parsed
            .refresh_token
            .filter(|t| !t.is_empty())
            .map(Secret::new),
        expires_in: parsed.expires_in.map(Duration::from_secs),
    })
}

/// Exchanges an authorization code (with its PKCE verifier) for tokens.
pub fn exchange_code(
    provider: &Provider,
    client_id: &str,
    redirect_uri: &str,
    code: &str,
    verifier: &str,
) -> Result<TokenSet> {
    request_tokens(
        &provider.token_endpoint,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", verifier),
        ],
        &[code, verifier],
    )
    .map_err(Error::Auth)
}

/// Exchanges a refresh token for a new token set. The provider may rotate the refresh token.
pub fn refresh(
    provider: &Provider,
    client_id: &str,
    refresh_token: &Secret,
) -> std::result::Result<TokenSet, String> {
    request_tokens(
        &provider.token_endpoint,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token.expose()),
            ("client_id", client_id),
        ],
        &[refresh_token.expose()],
    )
}

/// Revokes a token at the provider, when it has a revocation endpoint. Best effort.
pub fn revoke(
    provider: &Provider,
    client_id: &str,
    token: &Secret,
) -> std::result::Result<(), String> {
    let Some(endpoint) = &provider.revocation_endpoint else {
        return Ok(());
    };
    let http = http_client().map_err(|e| e.to_string())?;
    let response = http
        .post(endpoint)
        .form(&[("token", token.expose()), ("client_id", client_id)])
        .send()
        .map_err(|_| "could not reach the revocation endpoint".to_string())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!(
            "the revocation endpoint answered HTTP {}",
            response.status().as_u16()
        ))
    }
}

/// Decodes unpadded base64url, enough to read a JWT payload.
fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for byte in input.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => break,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Reads the `exp` claim of a JWT without verifying it (the broker verifies; this only decides
/// when to refresh).
pub fn jwt_expiry(token: &Secret) -> Option<OffsetDateTime> {
    let payload = token.expose().split('.').nth(1)?;
    let json = base64url_decode(payload)?;
    let value: serde_json::Value = serde_json::from_slice(&json).ok()?;
    let exp = value.get("exp")?.as_i64()?;
    OffsetDateTime::from_unix_timestamp(exp).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_exp_claim_of_a_jwt() {
        // {"alg":"none"}.{"exp":4102444800}.sig
        let token = Secret::new("eyJhbGciOiJub25lIn0.eyJleHAiOjQxMDI0NDQ4MDB9.sig");
        assert_eq!(jwt_expiry(&token).unwrap().unix_timestamp(), 4_102_444_800);
        assert!(jwt_expiry(&Secret::new("not-a-jwt")).is_none());
    }

    #[test]
    fn describe_never_shows_bodies_or_secrets() {
        let body = r#"{"error":"invalid_grant","error_description":"bad code SECRET-1"}"#;
        let text = describe(400, body, &["SECRET-1"]);
        assert!(text.contains("invalid_grant") && !text.contains("SECRET-1"));
        let text = describe(500, "<html>SECRET-2</html>", &["SECRET-2"]);
        assert_eq!(text, "the token endpoint answered HTTP 500");
    }
}
