//! Shared helpers for the integration tests. Everything uses fake credentials, local files and
//! loopback mock servers; real credentials are never used (constitution IX).

#![allow(dead_code)]

pub mod broker;
pub mod cloudflare;
pub mod mock;
pub mod provider;

use std::{
    io::{BufRead, BufReader},
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command as StdCommand, Stdio},
    sync::{Arc, Mutex},
};

use assert_cmd::Command;

/// Distinctive fake secrets that must never leak.
pub const FAKE_TOKEN: &str = "FAKE_STATIC_TOKEN_91bc";
pub const FAKE_ENV_TOKEN: &str = "FAKE_ENV_TOKEN_77aa";
pub const FAKE_ID_TOKEN_ENV: &str = "FAKE_ID_TOKEN_ENV_55cc.payload.sig";
pub const SENTINEL: &str = "SENTINEL-SECRET-123";

/// Path of the binary under test.
pub fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_cf-vault"))
}

/// A free loopback port (bound and released; fine for tests).
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A temporary home with a configuration file, test store and state directory.
pub struct Workspace {
    pub dir: tempfile::TempDir,
    /// Extra environment for every invocation.
    pub extra_env: Vec<(String, String)>,
}

impl Workspace {
    pub fn new(config: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.toml"), config).unwrap();
        for sub in ["store", "state", "tmp"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        Workspace {
            dir,
            extra_env: Vec::new(),
        }
    }

    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    pub fn config_file(&self) -> PathBuf {
        self.path().join("config.toml")
    }

    pub fn store_dir(&self) -> PathBuf {
        self.path().join("store")
    }

    pub fn set_config(&self, config: &str) {
        std::fs::write(self.config_file(), config).unwrap();
    }

    /// Environment shared by every invocation.
    pub fn apply_env(&self, cmd: &mut StdCommand) {
        cmd.env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", self.path())
            .env("CF_VAULT_CONFIG", self.config_file())
            .env("CF_VAULT_STATE_DIR", self.path().join("state"))
            .env("CF_VAULT_STORE_DIR", self.store_dir())
            .env("CF_VAULT_RETRY_DELAY_MS", "50")
            .env("TMPDIR", self.path().join("tmp"));
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        }
    }

    /// A command for the binary under test (no terminal on standard input).
    pub fn cmd(&self) -> Command {
        let mut std_cmd = StdCommand::new(binary());
        self.apply_env(&mut std_cmd);
        let mut cmd = Command::from_std(std_cmd);
        cmd.write_stdin("");
        cmd
    }

    /// Like [`Workspace::cmd`], but `exec` treats standard input as a terminal.
    pub fn interactive(&self) -> Command {
        let mut cmd = self.cmd();
        cmd.env("CF_VAULT_FORCE_INTERACTIVE", "1");
        cmd
    }

    /// A `std` command with the same environment (for pty sessions and spawning).
    pub fn std_cmd(&self) -> StdCommand {
        let mut cmd = StdCommand::new(binary());
        self.apply_env(&mut cmd);
        cmd
    }

    /// Stores a session entry for `profile` as cf-vault would (see data-model.md).
    pub fn seed(&self, profile: &str, json: &str) {
        std::fs::write(self.store_dir().join(format!("{profile}.json")), json).unwrap();
    }

    pub fn seed_token(&self, profile: &str, token: &str) {
        self.seed(
            profile,
            &format!("{{\"version\":1,\"kind\":\"token\",\"access_token\":\"{token}\"}}"),
        );
    }

    /// Stores an OAuth session. `expires_in` is seconds from now (negative: past).
    pub fn seed_oauth(
        &self,
        profile: &str,
        issuer: &str,
        access: &str,
        refresh: Option<&str>,
        expires_in: i64,
        id_token: Option<&str>,
    ) {
        let at = |secs: i64| time_rfc3339(provider::now() + secs);
        let refresh = refresh
            .map(|r| format!(",\"refresh_token\":\"{r}\""))
            .unwrap_or_default();
        let id = id_token
            .map(|t| {
                format!(
                    ",\"id_token\":\"{t}\",\"id_token_expires_at\":\"{}\"",
                    at(expires_in)
                )
            })
            .unwrap_or_default();
        self.seed(
            profile,
            &format!(
                "{{\"version\":1,\"kind\":\"oauth2\",\"access_token\":\"{access}\"{refresh}{id},\
                 \"expires_at\":\"{}\",\"issuer\":\"{issuer}\",\"client_id\":\"{}\"}}",
                at(expires_in),
                provider::CLIENT_ID
            ),
        );
    }

    /// The entry stored for `profile`, if any.
    pub fn stored(&self, profile: &str) -> Option<String> {
        std::fs::read_to_string(self.store_dir().join(format!("{profile}.json"))).ok()
    }

    /// Every file under the workspace, concatenated, for leak checks (the test store included,
    /// so tests that must find no secret on disk exclude `store/` themselves).
    pub fn all_text_except_store(&self) -> String {
        let mut out = String::new();
        let mut stack = vec![self.path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path == self.store_dir() {
                    continue;
                }
                if path.is_dir() {
                    stack.push(path);
                } else if let Ok(bytes) = std::fs::read(&path) {
                    out.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
        }
        out
    }
}

/// RFC 3339 UTC time from Unix seconds.
pub fn time_rfc3339(secs: i64) -> String {
    // Days since the epoch to civil date (Howard Hinnant's algorithm)
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// What a finished invocation printed.
pub struct Finished {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl Finished {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

/// A `login --no-browser` that is running and has printed its sign-in URL.
pub struct LoginRun {
    child: std::process::Child,
    stderr: Arc<Mutex<String>>,
    reader: Option<std::thread::JoinHandle<()>>,
    pub url: String,
}

/// Starts `cf-vault login -p <profile> --no-browser` and waits for the sign-in URL.
pub fn start_login(ws: &Workspace, profile: &str) -> LoginRun {
    let mut cmd = ws.std_cmd();
    cmd.args(["login", "-p", profile, "--no-browser"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    let stderr_pipe = child.stderr.take().unwrap();
    let stderr = Arc::new(Mutex::new(String::new()));
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let sink = stderr.clone();
    let reader = std::thread::spawn(move || {
        let mut sent = false;
        for line in BufReader::new(stderr_pipe).lines().map_while(Result::ok) {
            if !sent && line.starts_with("http") {
                sent = true;
                let _ = tx.send(line.clone());
            }
            let mut sink = sink.lock().unwrap();
            sink.push_str(&line);
            sink.push('\n');
        }
    });
    let url = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap_or_default();
    LoginRun {
        child,
        stderr,
        reader: Some(reader),
        url,
    }
}

impl LoginRun {
    /// Plays the browser: opens the sign-in URL, follows the redirect to cf-vault's callback.
    pub fn approve(&self) {
        let (status, headers, _) = mock::get(&self.url);
        assert_eq!(status, 302, "the provider did not redirect");
        let location = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("location"))
            .map(|(_, v)| v.clone())
            .expect("a Location header");
        let _ = mock::get(&location);
    }

    /// Calls the callback with a state of the test's choosing.
    pub fn callback_with(&self, query: &str) {
        let redirect = oauth2_redirect(&self.url);
        let _ = mock::get(&format!("{redirect}?{query}"));
    }

    pub fn finish(mut self) -> Finished {
        let status = self.child.wait().unwrap();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        let mut stdout = String::new();
        if let Some(mut out) = self.child.stdout.take() {
            use std::io::Read;
            let _ = out.read_to_string(&mut stdout);
        }
        Finished {
            code: status.code(),
            stdout,
            stderr: self.stderr.lock().unwrap().clone(),
        }
    }
}

/// The callback URL embedded in an authorization URL.
fn oauth2_redirect(url: &str) -> String {
    let query = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    mock::parse_pairs(query)
        .get("redirect_uri")
        .cloned()
        .unwrap_or_default()
}

/// Runs a whole sign-in: start, approve in the "browser", wait for the exit.
pub fn login(ws: &Workspace, profile: &str) -> Finished {
    let run = start_login(ws, profile);
    run.approve();
    run.finish()
}

/// Runs the binary with `args` and no terminal; returns what it printed.
pub fn run(ws: &Workspace, args: &[&str]) -> Finished {
    finish(ws.cmd().args(args).output().unwrap())
}

/// Like [`run`], with standard input treated as a terminal.
pub fn run_interactive(ws: &Workspace, args: &[&str]) -> Finished {
    finish(ws.interactive().args(args).output().unwrap())
}

fn finish(output: std::process::Output) -> Finished {
    Finished {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Fails when any of `secrets` appears in `text`.
pub fn assert_no_secrets(text: &str, secrets: &[&str]) {
    for secret in secrets {
        assert!(
            !text.contains(secret),
            "secret {secret:?} leaked into: {text}"
        );
    }
}

/// A config with an OAuth profile `personal` against `issuer` and a callback on `port`.
pub fn oauth_config(issuer: &str, port: u16) -> String {
    format!(
        "[personal]\ntype = \"oauth2\"\naccount_id = \"abc123\"\n\
         [personal.oauth2]\nissuer = \"{issuer}\"\nclient_id = \"{}\"\nredirect_port = {port}\n",
        provider::CLIENT_ID
    )
}
