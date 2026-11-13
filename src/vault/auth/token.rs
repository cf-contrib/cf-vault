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

/// The claims of an ID token that a client checks (OpenID Connect Core 3.1.3.7).
#[derive(Deserialize)]
struct IdClaims {
    #[serde(default)]
    iss: String,
    #[serde(default)]
    aud: serde_json::Value,
    #[serde(default)]
    exp: i64,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    iat: Option<i64>,
}

/// Checks an ID token the provider just issued: it is from `issuer`, for `client_id`, not yet
/// expired and, for a sign-in, for this sign-in (`nonce`). The signature is not checked: the
/// token came straight from the token endpoint over TLS (OpenID Connect Core 3.1.3.7, item 6),
/// and a broker verifies it again on every exchange.
pub fn check_id_token(
    token: &Secret,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
) -> std::result::Result<(), String> {
    let payload = token
        .expose()
        .split('.')
        .nth(1)
        .and_then(base64url_decode)
        .ok_or("the provider's ID token is not a JWT")?;
    let claims: IdClaims = serde_json::from_slice(&payload)
        .map_err(|_| "the provider's ID token has unreadable claims")?;
    if claims.iss.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err("the provider's ID token is from another issuer".into());
    }
    let (for_client, several) = match &claims.aud {
        serde_json::Value::String(aud) => (aud == client_id, false),
        serde_json::Value::Array(auds) => (
            auds.iter().any(|a| a.as_str() == Some(client_id)),
            auds.len() > 1,
        ),
        _ => (false, false),
    };
    if !for_client {
        return Err("the provider's ID token is for another client".into());
    }
    // With several audiences, the token must say which client it was issued to
    // (OpenID Connect Core 3.1.3.7, items 3 and 4)
    if several && claims.azp.as_deref() != Some(client_id) {
        return Err(
            "the provider's ID token names several audiences but was not issued to this client \
             (azp)"
                .into(),
        );
    }
    if let Some(nonce) = nonce {
        match claims.nonce.as_deref() {
            Some(found) if found == nonce => {}
            Some(_) => return Err("the provider's ID token is not for this sign-in".into()),
            None => {
                return Err(
                    "the provider's ID token does not carry the nonce cf-vault sent; \
                            the provider may not support nonces"
                        .into(),
                )
            }
        }
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if claims.exp <= now {
        // A token that was only just issued should be dated about now: if it is not, the
        // clock is the likely culprit
        let skew = claims.iat.map(|iat| now - iat).unwrap_or(0);
        return Err(if skew.abs() > 120 {
            format!(
                "the provider's ID token has already expired, and its issue time is {} minutes \
                 {} by this machine's clock: check the system clock",
                skew.abs() / 60,
                if skew > 0 {
                    "in the past"
                } else {
                    "in the future"
                }
            )
        } else {
            "the provider's ID token has already expired".into()
        });
    }
    Ok(())
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

    fn jwt(claims: &str) -> Secret {
        let encode = |bytes: &[u8]| {
            const A: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            for chunk in bytes.chunks(3) {
                let n = chunk
                    .iter()
                    .enumerate()
                    .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
                for i in 0..=chunk.len() {
                    out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
                }
            }
            out
        };
        Secret::new(format!(
            "{}.{}.sig",
            encode(b"{}"),
            encode(claims.as_bytes())
        ))
    }

    #[test]
    fn id_token_checks() {
        let far = OffsetDateTime::now_utc().unix_timestamp() + 3600;
        let good = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":"c","exp":{far},"nonce":"n1"}}"#
        ));
        check_id_token(&good, "https://id.example", "c", Some("n1")).unwrap();
        // A refreshed token has no nonce to match
        check_id_token(&good, "https://id.example/", "c", None).unwrap();
        let err = |token: &Secret, issuer, client, nonce| {
            check_id_token(token, issuer, client, nonce).unwrap_err()
        };
        assert!(err(&good, "https://other.example", "c", None).contains("another issuer"));
        assert!(err(&good, "https://id.example", "other", None).contains("another client"));
        assert!(err(&good, "https://id.example", "c", Some("n2")).contains("this sign-in"));
        let array = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":["x","c"],"azp":"c","exp":{far}}}"#
        ));
        check_id_token(&array, "https://id.example", "c", None).unwrap();
        let expired = jwt(r#"{"iss":"https://id.example","aud":"c","exp":1}"#);
        assert!(err(&expired, "https://id.example", "c", None).contains("expired"));
        // Several audiences need an azp that names this client
        let no_azp = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":["x","c"],"exp":{far}}}"#
        ));
        assert!(err(&no_azp, "https://id.example", "c", None).contains("azp"));
        let bad_azp = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":["x","c"],"azp":"x","exp":{far}}}"#
        ));
        assert!(err(&bad_azp, "https://id.example", "c", None).contains("azp"));
        let good_azp = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":["x","c"],"azp":"c","exp":{far}}}"#
        ));
        check_id_token(&good_azp, "https://id.example", "c", None).unwrap();
        // One audience in an array needs no azp
        let one = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":["c"],"exp":{far}}}"#
        ));
        check_id_token(&one, "https://id.example", "c", None).unwrap();
        // A missing nonce says so, a wrong one says it is not for this sign-in
        let no_nonce = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":"c","exp":{far}}}"#
        ));
        assert!(err(&no_nonce, "https://id.example", "c", Some("n1"))
            .contains("does not carry the nonce"));
        // An expired token dated far from now points at the clock
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let skewed = jwt(&format!(
            r#"{{"iss":"https://id.example","aud":"c","iat":{},"exp":{}}}"#,
            now - 3600,
            now - 3300
        ));
        let message = err(&skewed, "https://id.example", "c", None);
        assert!(
            message.contains("system clock") && message.contains("in the past"),
            "{message}"
        );
        assert!(err(&Secret::new("nope"), "https://id.example", "c", None).contains("not a JWT"));
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
