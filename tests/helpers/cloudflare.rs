//! A scripted Cloudflare API: token verify and R2 temporary credentials.

use std::sync::{Arc, Mutex};

use super::mock::{Handler, Request, Response, Server};

pub struct State {
    /// Answer the temp-credentials call with Cloudflare's code 10000.
    pub deny_r2: bool,
}

pub struct Cloudflare {
    pub server: Server,
    pub state: Arc<Mutex<State>>,
}

impl Cloudflare {
    pub fn start() -> Self {
        let state = Arc::new(Mutex::new(State { deny_r2: false }));
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
    let state = state.lock().unwrap();
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/accounts/abc123/tokens/verify") => Response::json(
            200,
            "{\"success\":true,\"result\":{\"id\":\"FAKE_TOKEN_ID\",\"status\":\"active\"}}",
        ),
        ("POST", "/accounts/abc123/r2/temp-access-credentials") => {
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
