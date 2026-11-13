//! A scripted token broker following the cloudflare-sts contract (contracts/broker.md).

use std::sync::{Arc, Mutex};

use super::mock::{Handler, Request, Response, Server};

/// Knobs a test can turn while the broker runs.
pub struct State {
    /// `(status, body)` to answer the next exchanges with, instead of the success body.
    pub fail_with: Vec<(u16, String)>,
    /// The account id the exchange answers for.
    pub account_id: String,
    /// Whether the profile has a token.
    pub with_token: bool,
    /// Whether the profile has a bucket.
    pub with_bucket: bool,
    /// Identity providers listed in the metadata: `(name, issuer, client_id)`.
    pub providers: Vec<(String, String, String)>,
    /// Status the revocation endpoint answers with.
    pub revoke_status: u16,
}

pub struct Broker {
    pub server: Server,
    pub state: Arc<Mutex<State>>,
}

impl Broker {
    pub fn start(providers: Vec<(String, String, String)>, account_id: &str) -> Self {
        let state = Arc::new(Mutex::new(State {
            fail_with: Vec::new(),
            account_id: account_id.to_string(),
            with_token: true,
            with_bucket: false,
            providers,
            revoke_status: 200,
        }));
        let shared = state.clone();
        let server = Server::start(move |base| -> Handler {
            Box::new(move |request| handle(&base, &shared, request))
        });
        Broker { server, state }
    }

    pub fn url(&self) -> String {
        self.server.url()
    }
}

fn handle(base: &str, state: &Arc<Mutex<State>>, request: &Request) -> Response {
    let mut state = state.lock().unwrap();
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/.well-known/oauth-authorization-server") => {
            let providers: Vec<String> = state
                .providers
                .iter()
                .map(|(n, i, c)| {
                    format!("{{\"name\":\"{n}\",\"issuer\":\"{i}\",\"client_id\":\"{c}\"}}")
                })
                .collect();
            Response::json(
                200,
                format!(
                    "{{\"issuer\":\"{base}\",\"token_endpoint\":\"{base}/oauth/token\",\
                     \"revocation_endpoint\":\"{base}/oauth/revoke\",\
                     \"identity_providers\":[{}]}}",
                    providers.join(",")
                ),
            )
        }
        ("POST", "/oauth/token") => {
            if !state.fail_with.is_empty() {
                let (status, body) = state.fail_with.remove(0);
                return Response::json(status, body);
            }
            let form = request.form();
            let profile = form.get("profile").cloned().unwrap_or_default();
            let mut body = String::from("{");
            if state.with_token {
                body.push_str("\"access_token\":\"FAKE_BROKER_TOKEN\",\"token_id\":\"3f2a9c\",");
            }
            let token_type = if state.with_token { "Bearer" } else { "N_A" };
            body.push_str(&format!(
                "\"issued_token_type\":\"urn:ietf:params:oauth:token-type:access_token\",\
                 \"token_type\":\"{token_type}\",\"expires_in\":900,\"expires_at\":{},\
                 \"account_id\":\"{}\",\"profile\":\"{profile}\"",
                super::provider::now() + 900,
                state.account_id
            ));
            if state.with_bucket {
                body.push_str(
                    ",\"bucket\":{\"name\":\"org-state\",\"access_key_id\":\"FAKE_R2_KEY\",\
                     \"secret_access_key\":\"FAKE_R2_SECRET\",\"session_token\":\"FAKE_R2_SESSION\",\
                     \"prefixes\":[\"repo/\"],\"endpoint\":\"https://abc.r2.cloudflarestorage.com\",\
                     \"expires_on\":\"2030-01-01T00:00:00Z\"}",
                );
            }
            body.push('}');
            Response::json(200, body)
        }
        ("POST", "/oauth/revoke") => Response::json(state.revoke_status, ""),
        _ => Response::json(404, "{}"),
    }
}
