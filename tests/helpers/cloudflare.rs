//! A scripted Cloudflare API: token verify, R2 temporary credentials, and the token endpoints a
//! session uses to mint a short-lived parent token.

use std::sync::{Arc, Mutex};

use super::mock::{Handler, Request, Response, Server};

/// The value of the token the scripted API "mints".
pub const MINTED_TOKEN: &str = "FAKE_MINTED_TOKEN";
/// Its id, which is the parent access key id of the temporary credentials.
pub const MINTED_ID: &str = "minted-id";

pub struct State {
    /// Answer the temp-credentials call with Cloudflare's code 10000.
    pub deny_r2: bool,
    /// Refuse to create a token.
    pub deny_mint: bool,
    /// How many temp-credentials calls with the minted token answer `401` before one succeeds
    /// (a fresh token takes a moment to be accepted).
    pub propagation_failures: u32,
    seen_with_minted: u32,
}

pub struct Cloudflare {
    pub server: Server,
    pub state: Arc<Mutex<State>>,
}

impl Cloudflare {
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(State {
            deny_r2: false,
            deny_mint: false,
            propagation_failures: 0,
            seen_with_minted: 0,
        }));
        let shared = state.clone();
        let server = Server::start(move |_| -> Handler {
            Box::new(move |request| handle(&shared, request))
        });
        Cloudflare { server, state }
    }

    /// The value for `CF_VAULT_API_URL`.
    pub fn api_url(&self) -> String {
        self.server.url()
    }
}

fn handle(state: &Arc<Mutex<State>>, request: &Request) -> Response {
    let mut state = state.lock().unwrap();
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/accounts/abc123/tokens/verify") => Response::json(
            200,
            "{\"success\":true,\"result\":{\"id\":\"FAKE_TOKEN_ID\",\"status\":\"active\"}}",
        ),
        ("GET", "/accounts/abc123/tokens/permission_groups") => Response::json(
            200,
            "{\"success\":true,\"result\":[\
             {\"id\":\"grp-other\",\"name\":\"DNS Write\"},\
             {\"id\":\"grp-w\",\"name\":\"Workers R2 Storage Write\"},\
             {\"id\":\"grp-r\",\"name\":\"Workers R2 Storage Read\"}]}",
        ),
        ("POST", "/accounts/abc123/tokens") => {
            if state.deny_mint {
                return Response::json(
                    403,
                    "{\"success\":false,\"errors\":[{\"code\":9109,\"message\":\"Unauthorized to access requested resource\"}]}",
                );
            }
            Response::json(
                200,
                format!(
                    "{{\"success\":true,\"result\":{{\"id\":\"{MINTED_ID}\",\"value\":\"{MINTED_TOKEN}\"}}}}"
                ),
            )
        }
        ("DELETE", path) if path == format!("/accounts/abc123/tokens/{MINTED_ID}") => {
            Response::json(200, "{\"success\":true,\"result\":{\"id\":\"minted-id\"}}")
        }
        ("POST", "/accounts/abc123/r2/temp-access-credentials") => {
            let bearer = request.header("authorization").unwrap_or_default();
            if bearer == format!("Bearer {MINTED_TOKEN}") {
                state.seen_with_minted += 1;
                if state.seen_with_minted <= state.propagation_failures {
                    return Response::json(
                        401,
                        "{\"success\":false,\"errors\":[{\"code\":10002,\"message\":\"Unauthorized\"}]}",
                    );
                }
            }
            if state.deny_r2 {
                return Response::json(
                    403,
                    "{\"success\":false,\"errors\":[{\"code\":10000,\"message\":\"Authentication error\"}]}",
                );
            }
            Response::json(
                200,
                "{\"success\":true,\"result\":{\"accessKeyId\":\"FAKE_TEMP_KEY\",\
                 \"secretAccessKey\":\"FAKE_TEMP_SECRET\",\"sessionToken\":\"FAKE_TEMP_SESSION\"}}",
            )
        }
        _ => Response::json(404, "{\"success\":false,\"errors\":[]}"),
    }
}
