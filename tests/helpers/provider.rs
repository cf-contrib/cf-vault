//! A scripted OIDC provider: discovery, an authorize endpoint that redirects straight back (the
//! "browser"), a token endpoint with PKCE checking, refresh and revocation. Fake tokens only.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use sha2::{Digest, Sha256};

use super::mock::{Handler, Request, Response, Server};

pub const CLIENT_ID: &str = "fake-client";

pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (*b as u32) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// A JWT-shaped fake with the given claims (JSON text).
pub fn jwt_with(claims: &str) -> String {
    format!(
        "{}.{}.fakesig",
        base64url(b"{\"alg\":\"none\"}"),
        base64url(claims.as_bytes())
    )
}

/// A JWT-shaped fake with the given expiry (seconds since the epoch).
pub fn fake_jwt(exp: i64, seed: &str) -> String {
    jwt_with(&format!("{{\"exp\":{exp},\"sub\":\"{seed}\"}}"))
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Knobs a test can turn while the provider runs.
pub struct State {
    pub access_lifetime: u64,
    pub id_lifetime: i64,
    pub rotate_refresh: bool,
    pub refresh_fails: bool,
    pub issue_id_token: bool,
    /// Put this in the ID token's `iss` instead of the provider's own issuer.
    pub id_iss: Option<String>,
    /// Put this in the ID token's `aud` instead of the client id.
    pub id_aud: Option<String>,
    /// Leave the sign-in's nonce out of the ID token.
    pub omit_nonce: bool,
    issued: u32,
    challenges: HashMap<String, String>,
    nonces: HashMap<String, String>,
}

pub struct Provider {
    pub server: Server,
    pub state: Arc<Mutex<State>>,
}

impl Provider {
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(State {
            access_lifetime: 3600,
            id_lifetime: 3600,
            rotate_refresh: true,
            refresh_fails: false,
            issue_id_token: true,
            id_iss: None,
            id_aud: None,
            omit_nonce: false,
            issued: 0,
            challenges: HashMap::new(),
            nonces: HashMap::new(),
        }));
        let shared = state.clone();
        let server = Server::start(move |base| -> Handler {
            Box::new(move |request| handle(&base, &shared, request))
        });
        Provider { server, state }
    }

    pub fn url(&self) -> String {
        self.server.url()
    }

    /// Form bodies of the token requests with the given `grant_type`.
    pub fn token_requests(&self, grant: &str) -> Vec<HashMap<String, String>> {
        self.server
            .hits("/token")
            .iter()
            .map(|r| r.form())
            .filter(|f| f.get("grant_type").map(String::as_str) == Some(grant))
            .collect()
    }
}

fn token_json(
    base: &str,
    state: &mut State,
    rotated: bool,
    previous: Option<&str>,
    nonce: Option<&str>,
) -> Response {
    state.issued += 1;
    let n = state.issued;
    let refresh = if rotated {
        format!("FAKE_REFRESH_{n}")
    } else {
        previous.unwrap_or("FAKE_REFRESH_1").to_string()
    };
    let mut body = format!(
        "{{\"access_token\":\"FAKE_ACCESS_{n}\",\"refresh_token\":\"{refresh}\",\
         \"expires_in\":{},\"token_type\":\"bearer\"",
        state.access_lifetime
    );
    if state.issue_id_token {
        let iss = state.id_iss.clone().unwrap_or_else(|| base.to_string());
        let aud = state
            .id_aud
            .clone()
            .unwrap_or_else(|| CLIENT_ID.to_string());
        let nonce = match nonce {
            Some(nonce) if !state.omit_nonce => format!(",\"nonce\":\"{nonce}\""),
            _ => String::new(),
        };
        let claims = format!(
            "{{\"iss\":\"{iss}\",\"aud\":\"{aud}\",\"sub\":\"id{n}\",\"exp\":{}{nonce}}}",
            now() + state.id_lifetime
        );
        body.push_str(&format!(",\"id_token\":\"{}\"", jwt_with(&claims)));
    }
    body.push('}');
    Response::json(200, body)
}

fn handle(base: &str, state: &Arc<Mutex<State>>, request: &Request) -> Response {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/.well-known/openid-configuration") => Response::json(
            200,
            format!(
                "{{\"issuer\":\"{base}\",\"authorization_endpoint\":\"{base}/authorize\",\
                 \"token_endpoint\":\"{base}/token\",\"revocation_endpoint\":\"{base}/revoke\",\
                 \"scopes_supported\":[\"openid\",\"offline_access\"]}}"
            ),
        ),
        ("GET", "/authorize") => {
            let q = request.query_map();
            let (Some(redirect), Some(state_param)) = (q.get("redirect_uri"), q.get("state"))
            else {
                return Response::json(400, "{\"error\":\"invalid_request\"}");
            };
            if q.get("code_challenge_method").map(String::as_str) != Some("S256") {
                return Response::json(400, "{\"error\":\"invalid_request\"}");
            }
            {
                let mut state = state.lock().unwrap();
                state.challenges.insert(
                    "FAKE_CODE".to_string(),
                    q.get("code_challenge").cloned().unwrap_or_default(),
                );
                state.nonces.insert(
                    "FAKE_CODE".to_string(),
                    q.get("nonce").cloned().unwrap_or_default(),
                );
            }
            let location = format!("{redirect}?code=FAKE_CODE&state={state_param}");
            Response::redirect(&location)
        }
        ("POST", "/token") => {
            let form = request.form();
            let mut state = state.lock().unwrap();
            match form.get("grant_type").map(String::as_str) {
                Some("authorization_code") => {
                    let verifier = form.get("code_verifier").cloned().unwrap_or_default();
                    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
                    let expected = state.challenges.get("FAKE_CODE").cloned();
                    if form.get("code").map(String::as_str) != Some("FAKE_CODE")
                        || expected.as_deref() != Some(challenge.as_str())
                    {
                        return Response::json(
                            400,
                            "{\"error\":\"invalid_grant\",\"error_description\":\"bad code or verifier\"}",
                        );
                    }
                    let nonce = state.nonces.get("FAKE_CODE").cloned();
                    token_json(base, &mut state, true, None, nonce.as_deref())
                }
                Some("refresh_token") => {
                    if state.refresh_fails {
                        return Response::json(
                            400,
                            "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token revoked\"}",
                        );
                    }
                    let previous = form.get("refresh_token").cloned();
                    let rotate = state.rotate_refresh;
                    token_json(base, &mut state, rotate, previous.as_deref(), None)
                }
                _ => Response::json(400, "{\"error\":\"unsupported_grant_type\"}"),
            }
        }
        ("POST", "/revoke") => Response::json(200, "{}"),
        _ => Response::json(404, "{}"),
    }
}
