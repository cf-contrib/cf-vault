//! The authorization code flow with PKCE (S256) and a loopback redirect. Adapted from
//! nix-vault's code flow (MIT): endpoints come from OIDC discovery and the ID token is kept.

use std::{
    io::{IsTerminal, Read, Write},
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

use oauth2::{url::Url, CsrfToken, PkceCodeChallenge};

use crate::vault::{
    auth::token::{exchange_code, Provider, TokenSet},
    Error, Result,
};

/// How long to wait for the browser to come back.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// What the flow needs to know about the profile.
pub struct Request<'a> {
    /// Profile name, for messages.
    pub profile: &'a str,
    /// The identity provider's endpoints.
    pub provider: &'a Provider,
    /// The public client id.
    pub client_id: &'a str,
    /// Loopback port of the redirect (Cloudflare matches redirect URIs exactly).
    pub redirect_port: u16,
    /// Scopes to request.
    pub scopes: &'a [String],
    /// Print the URL instead of opening a browser.
    pub no_browser: bool,
}

fn timeout() -> Duration {
    #[cfg(feature = "test-store")]
    if let Some(ms) = std::env::var("CF_VAULT_CALLBACK_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        return Duration::from_millis(ms);
    }
    CALLBACK_TIMEOUT
}

/// Runs the flow: prints the authorization URL, waits for the redirect on the loopback port,
/// checks `state`, and exchanges the code with the PKCE verifier.
pub fn login(request: &Request<'_>) -> Result<TokenSet> {
    let port = request.redirect_port;
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| {
        Error::io(
            &format!("cannot listen on port {port} for the browser redirect (is it in use?)"),
            e,
        )
    })?;
    let redirect = format!("http://127.0.0.1:{port}/callback");

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let state = CsrfToken::new_random();
    let mut url = Url::parse(&request.provider.authorization_endpoint)
        .map_err(|_| Error::Auth("the authorization endpoint is not a URL".into()))?;
    {
        let mut query = url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", request.client_id)
            .append_pair("redirect_uri", &redirect)
            .append_pair("state", state.secret())
            .append_pair("code_challenge", challenge.as_str())
            .append_pair("code_challenge_method", "S256");
        if !request.scopes.is_empty() {
            query.append_pair("scope", &request.scopes.join(" "));
        }
    }

    eprintln!(
        "To log in to {}, open this URL in a browser:\n{url}",
        request.profile
    );
    if !request.no_browser && std::io::stdin().is_terminal() {
        let _ = webbrowser::open(url.as_str());
    }
    eprintln!("Waiting for authorization...");

    let code = wait_for_callback(&listener, state.secret(), timeout())?;
    exchange_code(
        request.provider,
        request.client_id,
        &redirect,
        &code,
        verifier.secret(),
    )
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

/// Waits for the redirect with `code` and `state`, up to `timeout`.
pub fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| Error::io("cannot listen for the browser redirect", e))?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                let mut buffer = [0u8; 8192];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                let Ok(url) = Url::parse(&format!("http://127.0.0.1{target}")) else {
                    respond(&mut stream, "400 Bad Request", "bad request");
                    continue;
                };
                if url.path() != "/callback" {
                    respond(&mut stream, "404 Not Found", "not found");
                    continue;
                }
                let query = |key: &str| {
                    url.query_pairs()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.into_owned())
                };
                if let Some(error) = query("error") {
                    respond(
                        &mut stream,
                        "200 OK",
                        "Login failed. You can close this window.",
                    );
                    let error: String = error
                        .chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .take(60)
                        .collect();
                    return Err(Error::Auth(format!(
                        "the provider returned the error {error}"
                    )));
                }
                if query("state").as_deref() != Some(expected_state) {
                    respond(&mut stream, "400 Bad Request", "state mismatch");
                    return Err(Error::Auth(
                        "the redirect did not carry the expected state; login aborted".into(),
                    ));
                }
                let Some(code) = query("code") else {
                    respond(&mut stream, "400 Bad Request", "missing code");
                    return Err(Error::Auth(
                        "the redirect carried no authorization code".into(),
                    ));
                };
                respond(
                    &mut stream,
                    "200 OK",
                    "Logged in. You can close this window.",
                );
                return Ok(code);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Error::Auth(
                        "timed out waiting for the browser; run login again".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(Error::io("cannot accept the browser redirect", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gives_up_after_the_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let started = Instant::now();
        let error = wait_for_callback(&listener, "state", Duration::from_millis(200)).unwrap_err();
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    fn callback(listener: &TcpListener, query: &str) -> std::thread::JoinHandle<()> {
        let port = listener.local_addr().unwrap().port();
        let query = query.to_string();
        std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(stream, "GET /callback?{query} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
            let mut sink = String::new();
            let _ = stream.read_to_string(&mut sink);
        })
    }

    #[test]
    fn accepts_the_matching_state_and_rejects_others() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "code=abc&state=good");
        assert_eq!(
            wait_for_callback(&listener, "good", Duration::from_secs(5)).unwrap(),
            "abc"
        );
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "code=abc&state=evil");
        assert!(wait_for_callback(&listener, "good", Duration::from_secs(5)).is_err());
        handle.join().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let handle = callback(&listener, "error=access_denied&state=good");
        let error = wait_for_callback(&listener, "good", Duration::from_secs(5)).unwrap_err();
        assert!(error.to_string().contains("access_denied"));
        handle.join().unwrap();
    }
}
