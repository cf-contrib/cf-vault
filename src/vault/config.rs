//! Profile configuration: the TOML model, validation and the provider resolution matrix.
//!
//! The file holds no secrets. It is validated as a whole before any command acts, and every
//! error names the profile and the key concerned, never a value. The structure follows
//! nix-vault's configuration module (MIT); the model is cf-vault's (see data-model.md).

use std::path::{Path, PathBuf};

use toml::{Table, Value};

use crate::vault::{Error, Result};

/// Default loopback port of the sign-in callback. Cloudflare matches redirect URIs exactly, so
/// the port is fixed unless the profile says otherwise.
pub const DEFAULT_REDIRECT_PORT: u16 = 8250;

/// Keys that must never be stored in the configuration file.
const SECRET_KEYS: [&str; 6] = [
    "token",
    "secret",
    "password",
    "access_token",
    "client_secret",
    "id_token",
];
const PROFILE_KEYS: [&str; 4] = ["type", "account_id", "oauth2", "r2"];
const OAUTH_KEYS: [&str; 5] = ["issuer", "client_id", "scopes", "redirect_port", "exchange"];
const EXCHANGE_KEYS: [&str; 6] = [
    "issuer",
    "token_endpoint",
    "revocation_endpoint",
    "scopes",
    "audience",
    "provider",
];
const R2_KEYS: [&str; 3] = ["bucket", "permission", "prefixes"];

/// How a profile authenticates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A static Cloudflare API token kept in the credential store.
    ApiToken,
    /// OAuth 2.0 sign-in, optionally followed by a broker exchange.
    OAuth2(OAuth),
}

/// The `[<profile>.oauth2]` settings. Every field is optional.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OAuth {
    /// Issuer of an explicitly configured provider.
    pub issuer: Option<String>,
    /// Public client id registered at that provider.
    pub client_id: Option<String>,
    /// Requested scopes; empty means "use the default".
    pub scopes: Vec<String>,
    /// Loopback port of the sign-in callback.
    pub redirect_port: u16,
    /// Token exchange at a broker.
    pub exchange: Option<Box<Exchange>>,
}

/// The `[<profile>.oauth2.exchange]` settings: an RFC 8693 token exchange at a broker.
///
/// The broker is named by its `issuer`, whose metadata supplies the endpoints, or by its
/// endpoints; an endpoint written here always wins over the discovered one. At least one of
/// `issuer` and `token_endpoint` is set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Exchange {
    /// The broker's issuer (its URL); its metadata is read to fill in the endpoints and to
    /// learn which identity provider people sign in with.
    pub issuer: Option<String>,
    /// Where the token exchange is `POST`ed.
    pub token_endpoint: Option<String>,
    /// Where an issued token is revoked, when the broker has such an endpoint.
    pub revocation_endpoint: Option<String>,
    /// What to ask for (the `scope` of RFC 8693), sent space-separated; empty sends none.
    pub scopes: Vec<String>,
    /// The `audience` to ask for, when the broker wants one.
    pub audience: Option<String>,
    /// The broker's name for the identity provider, to pick one when it lists several.
    pub provider: Option<String>,
}

/// Which permission temporary R2 credentials carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission {
    /// Read and write objects (the default).
    ObjectReadWrite,
    /// Read objects only.
    ObjectReadOnly,
}

impl Permission {
    /// The value Cloudflare's API expects.
    pub fn as_api(self) -> &'static str {
        match self {
            Permission::ObjectReadWrite => "object-read-write",
            Permission::ObjectReadOnly => "object-read-only",
        }
    }
}

/// The `[<profile>.r2]` settings: exactly one bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct R2 {
    /// The bucket the credentials are limited to.
    pub bucket: String,
    /// Permission of the credentials.
    pub permission: Permission,
    /// Key prefixes the credentials are limited to; empty means the whole bucket.
    pub prefixes: Vec<String>,
}

/// One named profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// Table name.
    pub name: String,
    /// Cloudflare account id.
    pub account_id: String,
    /// How the profile authenticates.
    pub kind: Kind,
    /// Temporary R2 credentials, for profiles without a broker.
    pub r2: Option<R2>,
}

impl Profile {
    /// The broker settings, when the profile exchanges tokens.
    pub fn exchange(&self) -> Option<&Exchange> {
        match &self.kind {
            Kind::OAuth2(oauth) => oauth.exchange.as_deref(),
            Kind::ApiToken => None,
        }
    }
}

/// The identity provider a profile signs in with, before any network access (the resolution
/// matrix of data-model.md).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderSource {
    /// Cloudflare's own sign-in with the client registered for this tool.
    Cloudflare,
    /// A provider named in the profile.
    Explicit {
        /// Issuer URL.
        issuer: String,
        /// Client id.
        client_id: String,
    },
    /// The provider is discovered from the broker's metadata.
    Broker,
}

impl OAuth {
    /// Applies the resolution matrix.
    pub fn provider_source(&self) -> ProviderSource {
        match (&self.issuer, &self.client_id, &self.exchange) {
            (Some(issuer), Some(client_id), _) => ProviderSource::Explicit {
                issuer: issuer.clone(),
                client_id: client_id.clone(),
            },
            // Only a broker with an issuer has metadata to learn the provider from
            (_, _, Some(exchange)) if exchange.issuer.is_some() => ProviderSource::Broker,
            _ => ProviderSource::Cloudflare,
        }
    }
}

/// All profiles of the configuration file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Profiles in file order.
    pub profiles: Vec<Profile>,
}

/// Whether `url` is an acceptable endpoint: `https`, or `http` on a loopback address (used by
/// the loopback sign-in and by local test servers).
pub fn endpoint_allowed(url: &str) -> bool {
    let Ok(parsed) = oauth2::url::Url::parse(url) else {
        return false;
    };
    match parsed.scheme() {
        "https" => parsed.host_str().is_some(),
        "http" => matches!(
            parsed.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("[::1]")
        ),
        _ => false,
    }
}

fn valid_profile_name(name: &str) -> bool {
    let mut chars = name.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    first_ok
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

fn is_secret_key(key: &str) -> bool {
    SECRET_KEYS.contains(&key) || key.starts_with("refresh_")
}

/// Collects the problems of one profile so every profile is reported, not just the first.
struct Problems<'a> {
    profile: &'a str,
    out: &'a mut Vec<String>,
}

impl Problems<'_> {
    fn add(&mut self, message: impl std::fmt::Display) {
        self.out
            .push(format!("profile \"{}\": {message}", self.profile));
    }

    /// Reports unknown and secret-like keys of `table` at `path`.
    fn keys(&mut self, table: &Table, allowed: &[&str], path: &str) {
        for key in table.keys() {
            let full = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            if is_secret_key(key) {
                self.add(format!(
                    "secret-like key \"{full}\" is not allowed; use `cf-vault login -p {}`; \
                     secrets never go in config",
                    self.profile
                ));
            } else if !allowed.contains(&key.as_str()) {
                let hint = allowed
                    .iter()
                    .find(|candidate| close(candidate, key))
                    .map(|c| format!(" (did you mean \"{c}\"?)"))
                    .unwrap_or_default();
                self.add(format!("unknown key \"{full}\"{hint}"));
            }
        }
    }

    fn string(&mut self, table: &Table, key: &str, path: &str) -> Option<String> {
        match table.get(key) {
            None => None,
            Some(Value::String(s)) if !s.trim().is_empty() => Some(s.clone()),
            Some(Value::String(_)) => {
                self.add(format!("\"{path}{key}\" must not be empty"));
                None
            }
            Some(_) => {
                self.add(format!("\"{path}{key}\" must be a string"));
                None
            }
        }
    }

    fn strings(&mut self, table: &Table, key: &str, path: &str) -> Vec<String> {
        match table.get(key) {
            None => Vec::new(),
            Some(Value::Array(items)) => {
                let mut out = Vec::new();
                for item in items {
                    match item {
                        Value::String(s) if !s.is_empty() => out.push(s.clone()),
                        _ => {
                            self.add(format!(
                                "\"{path}{key}\" must be a list of non-empty strings"
                            ));
                            return Vec::new();
                        }
                    }
                }
                out
            }
            Some(_) => {
                self.add(format!("\"{path}{key}\" must be a list of strings"));
                Vec::new()
            }
        }
    }

    fn table<'t>(&mut self, table: &'t Table, key: &str, path: &str) -> Option<&'t Table> {
        match table.get(key) {
            None => None,
            Some(Value::Table(t)) => Some(t),
            Some(_) => {
                self.add(format!("\"{path}{key}\" must be a table"));
                None
            }
        }
    }
}

/// Two keys are "close" when they differ by one character or one is a prefix of the other's
/// misspelling; enough for a helpful hint.
fn close(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    if long.len() - short.len() > 1 {
        return false;
    }
    // Same length: at most one substitution; one longer: at most one insertion
    let (s, l): (Vec<char>, Vec<char>) = (short.chars().collect(), long.chars().collect());
    if s.len() == l.len() {
        s.iter().zip(&l).filter(|(x, y)| x != y).count() <= 1
    } else {
        (0..l.len()).any(|skip| {
            let reduced: Vec<char> = l
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, c)| *c)
                .collect();
            reduced == s
        })
    }
}

impl Config {
    /// Parses and validates configuration text. All problems of all profiles are reported
    /// together.
    pub fn parse(text: &str) -> Result<Config> {
        let root: Table = text.parse().map_err(|e: toml::de::Error| {
            // The message names a line and column, not values of secrets (none belong here)
            Error::config(format!("config: {}", e.message()))
        })?;
        let mut problems = Vec::new();
        let mut profiles = Vec::new();
        for (name, value) in &root {
            let mut p = Problems {
                profile: name,
                out: &mut problems,
            };
            let Value::Table(table) = value else {
                p.add("must be a table, as in [name]");
                continue;
            };
            if !valid_profile_name(name) {
                p.add(
                    "the name must be 1–64 characters of A-Za-z0-9_.- and start with a letter \
                     or digit",
                );
            }
            if let Some(profile) = parse_profile(name, table, &mut p) {
                profiles.push(profile);
            }
        }
        if problems.is_empty() {
            Ok(Config { profiles })
        } else {
            Err(Error::config(
                problems
                    .iter()
                    .map(|m| format!("config: {m}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ))
        }
    }

    /// Loads the configuration file at `path`.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::config(format!(
                    "no configuration file at {}; create one (see config.example.toml)",
                    path.display()
                ))
            } else {
                Error::io(&format!("cannot read {}", path.display()), e)
            }
        })?;
        Config::parse(&text)
    }

    /// Finds the profile named `name`, or fails listing the configured ones.
    pub fn profile(&self, name: &str) -> Result<&Profile> {
        self.profiles
            .iter()
            .find(|p| p.name == name)
            .ok_or_else(|| self.unknown(Some(name)))
    }

    /// The error for a missing or unknown profile name, listing what is configured.
    pub fn unknown(&self, name: Option<&str>) -> Error {
        let available = if self.profiles.is_empty() {
            "none configured".to_string()
        } else {
            self.profiles
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        match name {
            Some(name) => Error::config(format!(
                "unknown profile \"{name}\"; available profiles: {available}"
            )),
            None => Error::config(format!(
                "no profile selected; pass -p <name> or set CF_VAULT_PROFILE; available \
                 profiles: {available}"
            )),
        }
    }
}

fn parse_profile(name: &str, table: &Table, p: &mut Problems<'_>) -> Option<Profile> {
    let before = p.out.len();
    p.keys(table, &PROFILE_KEYS, "");
    let account_id = p.string(table, "account_id", "");
    if account_id.is_none() && !table.contains_key("account_id") {
        p.add("\"account_id\" is required");
    }
    let is_token = match table.get("type") {
        Some(Value::String(t)) if t == "api_token" => Some(true),
        Some(Value::String(t)) if t == "token" => {
            p.add("type \"token\" was renamed to \"api_token\"");
            None
        }
        Some(Value::String(t)) if t == "oauth2" => Some(false),
        Some(Value::String(t)) => {
            p.add(format!(
                "unknown type \"{t}\"; expected \"oauth2\" or \"api_token\""
            ));
            None
        }
        Some(_) => {
            p.add("\"type\" must be a string");
            None
        }
        None => {
            p.add("\"type\" is required (\"oauth2\" or \"api_token\")");
            None
        }
    };

    let oauth_table = p.table(table, "oauth2", "");
    let kind = match (is_token, oauth_table) {
        (Some(true), Some(_)) => {
            p.add("an [oauth2] table is only valid for type = \"oauth2\"");
            None
        }
        (Some(true), None) => Some(Kind::ApiToken),
        (Some(false), table) => Some(Kind::OAuth2(parse_oauth(table, p))),
        (None, _) => None,
    };

    if let Kind::OAuth2(oauth) = kind.as_ref().unwrap_or(&Kind::ApiToken) {
        if let Some(exchange) = &oauth.exchange {
            let own_provider = oauth.issuer.is_some() && oauth.client_id.is_some();
            if exchange.issuer.is_none() && !own_provider {
                p.add(
                    "\"oauth2.exchange\" has no \"issuer\" to learn the identity provider \
                     from, so \"oauth2.issuer\" and \"oauth2.client_id\" are required",
                );
            }
        }
    }

    let r2 = p.table(table, "r2", "").map(|t| parse_r2(t, p));
    if let (Some(Kind::OAuth2(oauth)), Some(_)) = (&kind, &r2) {
        if oauth.exchange.is_some() {
            p.add("\"r2\" is not allowed together with \"exchange\" (the broker profile decides)");
        }
    }

    if p.out.len() != before {
        return None;
    }
    Some(Profile {
        name: name.to_string(),
        account_id: account_id?,
        kind: kind?,
        r2: r2.flatten(),
    })
}

fn parse_oauth(table: Option<&Table>, p: &mut Problems<'_>) -> OAuth {
    let mut oauth = OAuth {
        redirect_port: DEFAULT_REDIRECT_PORT,
        ..OAuth::default()
    };
    let Some(table) = table else {
        return oauth;
    };
    p.keys(table, &OAUTH_KEYS, "oauth2");
    oauth.issuer = p.string(table, "issuer", "oauth2.");
    oauth.client_id = p.string(table, "client_id", "oauth2.");
    oauth.scopes = p.strings(table, "scopes", "oauth2.");
    match (&oauth.issuer, &oauth.client_id) {
        (Some(_), None) => p.add("\"oauth2.issuer\" requires \"oauth2.client_id\""),
        (None, Some(_)) => p.add("\"oauth2.client_id\" requires \"oauth2.issuer\""),
        _ => {}
    }
    if let Some(issuer) = &oauth.issuer {
        if !endpoint_allowed(issuer) {
            p.add("\"oauth2.issuer\" must be an https URL");
        }
    }
    match table.get("redirect_port") {
        None => {}
        Some(Value::Integer(port)) if (1..=65535).contains(port) => {
            oauth.redirect_port = *port as u16;
        }
        Some(_) => p.add("\"oauth2.redirect_port\" must be an integer from 1 to 65535"),
    }
    if let Some(exchange) = p.table(table, "exchange", "oauth2.") {
        oauth.exchange = parse_exchange(exchange, p).map(Box::new);
    }
    oauth
}

fn parse_exchange(table: &Table, p: &mut Problems<'_>) -> Option<Exchange> {
    // The old keys get one pointed message each, not an "unknown key" on top of it
    let current: Vec<&str> = EXCHANGE_KEYS.to_vec();
    let known: Vec<&str> = current.iter().copied().chain(["url", "profile"]).collect();
    p.keys(table, &known, "oauth2.exchange");
    let mut renamed = false;
    if table.contains_key("url") {
        p.add("\"oauth2.exchange.url\" was renamed to \"oauth2.exchange.issuer\"");
        renamed = true;
    }
    if table.contains_key("profile") {
        p.add("\"oauth2.exchange.profile\" was replaced by \"oauth2.exchange.scopes\"");
        renamed = true;
    }
    if renamed {
        return None;
    }
    let mut exchange = Exchange {
        issuer: p.string(table, "issuer", "oauth2.exchange."),
        token_endpoint: p.string(table, "token_endpoint", "oauth2.exchange."),
        revocation_endpoint: p.string(table, "revocation_endpoint", "oauth2.exchange."),
        scopes: p.strings(table, "scopes", "oauth2.exchange."),
        audience: p.string(table, "audience", "oauth2.exchange."),
        provider: p.string(table, "provider", "oauth2.exchange."),
    };
    if exchange.issuer.is_none()
        && exchange.token_endpoint.is_none()
        && !table.contains_key("issuer")
        && !table.contains_key("token_endpoint")
    {
        p.add("\"oauth2.exchange\" needs an \"issuer\" or a \"token_endpoint\"");
    }
    for (key, value) in [
        ("issuer", &mut exchange.issuer),
        ("token_endpoint", &mut exchange.token_endpoint),
        ("revocation_endpoint", &mut exchange.revocation_endpoint),
    ] {
        if let Some(url) = value {
            if !endpoint_allowed(url) {
                p.add(format!("\"oauth2.exchange.{key}\" must be an https URL"));
            }
            if key == "issuer" {
                *url = url.trim_end_matches('/').to_string();
            }
        }
    }
    if exchange
        .scopes
        .iter()
        .any(|s| s.contains(char::is_whitespace))
    {
        p.add("\"oauth2.exchange.scopes\" must not contain spaces; list one scope per item");
    }
    if exchange.provider.is_some() && exchange.issuer.is_none() {
        p.add(
            "\"oauth2.exchange.provider\" needs \"oauth2.exchange.issuer\" to read the list from",
        );
    }
    Some(exchange)
}

/// R2 bucket names: 3–63 characters of lowercase letters, digits and hyphens, starting and
/// ending with a letter or digit.
fn valid_bucket(name: &str) -> bool {
    let bytes = name.as_bytes();
    (3..=63).contains(&bytes.len())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
}

fn parse_r2(table: &Table, p: &mut Problems<'_>) -> Option<R2> {
    p.keys(table, &R2_KEYS, "r2");
    let bucket = match table.get("bucket") {
        None => {
            p.add("\"r2.bucket\" is required");
            None
        }
        Some(Value::String(b)) if valid_bucket(b) => Some(b.clone()),
        Some(Value::String(_)) => {
            p.add("\"r2.bucket\" is not a valid R2 bucket name");
            None
        }
        Some(Value::Array(_)) => {
            p.add("\"r2.bucket\" must be a single bucket name; use one profile per bucket");
            None
        }
        Some(_) => {
            p.add("\"r2.bucket\" must be a string");
            None
        }
    };
    let permission = match table.get("permission") {
        None => Permission::ObjectReadWrite,
        Some(Value::String(s)) if s == "object-read-write" => Permission::ObjectReadWrite,
        Some(Value::String(s)) if s == "object-read-only" => Permission::ObjectReadOnly,
        Some(_) => {
            p.add("\"r2.permission\" must be \"object-read-write\" or \"object-read-only\"");
            Permission::ObjectReadWrite
        }
    };
    let prefixes = p.strings(table, "prefixes", "r2.");
    Some(R2 {
        bucket: bucket?,
        permission,
        prefixes,
    })
}

fn base_dir(xdg: &str, fallback: &str) -> PathBuf {
    if let Some(dir) = std::env::var_os(xdg).filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default();
    home.join(fallback)
}

/// Returns the configuration path: `explicit` when given, else `$XDG_CONFIG_HOME/cf-vault` or
/// `~/.config/cf-vault`. (`CF_VAULT_CONFIG` reaches `explicit` through the command line parser.)
pub fn config_path(explicit: Option<&Path>) -> PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    base_dir("XDG_CONFIG_HOME", ".config")
        .join("cf-vault")
        .join("config.toml")
}

/// Returns the state directory (lock files only): `$CF_VAULT_STATE_DIR`, else
/// `$XDG_STATE_HOME/cf-vault`, else `~/.local/state/cf-vault`.
pub fn state_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("CF_VAULT_STATE_DIR") {
        return PathBuf::from(dir);
    }
    base_dir("XDG_STATE_HOME", ".local/state").join("cf-vault")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_err(text: &str) -> String {
        Config::parse(text).unwrap_err().to_string()
    }

    #[test]
    fn minimal_profiles_resolve_as_the_matrix_says() {
        let config = Config::parse(
            "[personal]\ntype=\"oauth2\"\naccount_id=\"abc123\"\n\
             [brokered]\ntype=\"oauth2\"\naccount_id=\"x\"\n\
             [brokered.oauth2.exchange]\nissuer = \"https://broker.example/\"\nscopes = [\"a:b\"]\n\
             [own]\ntype=\"oauth2\"\naccount_id=\"x\"\n\
             [own.oauth2]\nissuer=\"https://id.example\"\nclient_id=\"c\"\n\
             [both]\ntype=\"oauth2\"\naccount_id=\"x\"\n\
             [both.oauth2]\nissuer=\"https://id.example\"\nclient_id=\"c\"\n\
             [both.oauth2.exchange]\nissuer = \"https://broker.example\"\nscopes = [\"a:b\"]\n",
        )
        .unwrap();
        let source = |name: &str| match &config.profile(name).unwrap().kind {
            Kind::OAuth2(o) => o.provider_source(),
            Kind::ApiToken => unreachable!(),
        };
        assert_eq!(source("personal"), ProviderSource::Cloudflare);
        assert_eq!(source("brokered"), ProviderSource::Broker);
        assert!(matches!(source("own"), ProviderSource::Explicit { .. }));
        assert!(matches!(source("both"), ProviderSource::Explicit { .. }));
        let exchange = config.profile("brokered").unwrap().exchange().unwrap();
        assert_eq!(exchange.issuer.as_deref(), Some("https://broker.example"));
        assert_eq!(exchange.scopes, vec!["a:b".to_string()]);
    }

    #[test]
    fn rejects_secrets_unknown_keys_and_bad_types() {
        let e = parse_err("[a]\ntype=\"api_token\"\naccount_id=\"x\"\ntoken=\"s\"\n");
        assert!(e.contains("secret-like key \"token\"") && e.contains("cf-vault login -p a"));
        assert!(!e.contains("\"s\""));
        let e =
            parse_err("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nrefresh_foo=\"v\"\n");
        assert!(e.contains("secret-like key \"oauth2.refresh_foo\""));
        let e =
            parse_err("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2.exhange]\nurl=\"u\"\n");
        assert!(e.contains("unknown key \"oauth2.exhange\"") && e.contains("did you mean"));
        let e = parse_err("[a]\ntype=\"nope\"\naccount_id=\"x\"\n");
        assert!(e.contains("profile \"a\"") && e.contains("unknown type \"nope\""));
        let e = parse_err("[a]\ntype=\"api_token\"\n");
        assert!(e.contains("\"account_id\" is required"));
    }

    #[test]
    fn issuer_and_client_id_go_together_and_must_be_https() {
        let e = parse_err("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nclient_id=\"c\"\n");
        assert!(e.contains("requires \"oauth2.issuer\""));
        let e =
            parse_err("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nissuer=\"https://i\"\n");
        assert!(e.contains("requires \"oauth2.client_id\""));
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nissuer=\"http://example.com\"\nclient_id=\"c\"\n",
        );
        assert!(e.contains("must be an https URL"));
        // loopback http is accepted
        Config::parse(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nissuer=\"http://127.0.0.1:9\"\nclient_id=\"c\"\n",
        )
        .unwrap();
    }

    #[test]
    fn exchange_needs_an_issuer_or_a_token_endpoint() {
        let e = parse_err("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2.exchange]\n");
        assert!(
            e.contains("needs an \"issuer\" or a \"token_endpoint\""),
            "{e}"
        );
    }

    #[test]
    fn the_old_exchange_keys_point_at_the_new_ones() {
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2.exchange]\nurl=\"https://b\"\nprofile=\"p\"\n",
        );
        assert!(
            e.contains("\"oauth2.exchange.url\" was renamed to \"oauth2.exchange.issuer\""),
            "{e}"
        );
        assert!(
            e.contains("\"oauth2.exchange.profile\" was replaced by"),
            "{e}"
        );
    }

    #[test]
    fn exchange_endpoints_scopes_and_audience_are_read() {
        let config = Config::parse(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n\
             [a.oauth2]\nissuer=\"https://id.example\"\nclient_id=\"c\"\n\
             [a.oauth2.exchange]\ntoken_endpoint=\"https://b.example/token\"\n\
             revocation_endpoint=\"https://b.example/revoke\"\n\
             scopes=[\"one\",\"two\"]\naudience=\"https://api.example\"\n",
        )
        .unwrap();
        let exchange = config.profile("a").unwrap().exchange().unwrap();
        assert_eq!(exchange.issuer, None);
        assert_eq!(
            exchange.token_endpoint.as_deref(),
            Some("https://b.example/token")
        );
        assert_eq!(
            exchange.revocation_endpoint.as_deref(),
            Some("https://b.example/revoke")
        );
        assert_eq!(exchange.scopes, vec!["one".to_string(), "two".to_string()]);
        assert_eq!(exchange.audience.as_deref(), Some("https://api.example"));
        // The provider is the explicit one: there is no metadata to learn it from
        assert!(matches!(
            match &config.profile("a").unwrap().kind {
                Kind::OAuth2(o) => o.provider_source(),
                Kind::ApiToken => unreachable!(),
            },
            ProviderSource::Explicit { .. }
        ));
    }

    #[test]
    fn without_an_issuer_the_provider_must_be_explicit() {
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2.exchange]\ntoken_endpoint=\"https://b/token\"\n",
        );
        assert!(
            e.contains("\"oauth2.issuer\" and \"oauth2.client_id\" are required"),
            "{e}"
        );
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2]\nissuer=\"https://i\"\nclient_id=\"c\"\n\
             [a.oauth2.exchange]\ntoken_endpoint=\"https://b/token\"\nprovider=\"idp\"\n",
        );
        assert!(e.contains("\"oauth2.exchange.provider\" needs"), "{e}");
    }

    #[test]
    fn exchange_urls_and_scopes_are_checked() {
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.oauth2.exchange]\nissuer=\"http://b.example\"\n\
             revocation_endpoint=\"ftp://b\"\nscopes=[\"two words\"]\n",
        );
        assert!(e.contains("exchange.issuer\" must be an https URL"), "{e}");
        assert!(
            e.contains("exchange.revocation_endpoint\" must be an https URL"),
            "{e}"
        );
        assert!(e.contains("must not contain spaces"), "{e}");
    }

    #[test]
    fn r2_is_one_bucket_and_never_with_a_broker() {
        let ok = Config::parse(
            "[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"tf-state\"\npermission=\"object-read-only\"\nprefixes=[\"p/\"]\n",
        )
        .unwrap();
        let r2 = ok.profiles[0].r2.clone().unwrap();
        assert_eq!(r2.permission, Permission::ObjectReadOnly);
        assert_eq!(r2.prefixes, vec!["p/".to_string()]);
        let default = Config::parse(
            "[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"tf-state\"\n",
        )
        .unwrap();
        assert_eq!(
            default.profiles[0].r2.as_ref().unwrap().permission,
            Permission::ObjectReadWrite
        );

        let e = parse_err(
            "[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.r2]\nbucket=[\"one\",\"two\"]\n",
        );
        assert!(e.contains("use one profile per bucket"));
        let e =
            parse_err("[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"Bad_Name\"\n");
        assert!(e.contains("not a valid R2 bucket name"));
        let e = parse_err("[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"tf-state\"\npermission=\"admin\"\n");
        assert!(e.contains("r2.permission"));
        // An OAuth profile may name a bucket too: a token is minted as the parent
        Config::parse("[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"tf-state\"\n")
            .unwrap();
        let e = parse_err(
            "[a]\ntype=\"oauth2\"\naccount_id=\"x\"\n[a.r2]\nbucket=\"tf-state\"\n\
             [a.oauth2.exchange]\nissuer = \"https://b\"\nscopes = [\"p\"]\n",
        );
        assert!(e.contains("not allowed together with \"exchange\""));
    }

    #[test]
    fn names_are_validated_and_all_profiles_are_reported() {
        let e = parse_err(
            "[\"-bad\"]\ntype=\"api_token\"\naccount_id=\"x\"\n[ok]\ntype=\"nope\"\naccount_id=\"x\"\n",
        );
        assert!(e.contains("profile \"-bad\"") && e.contains("profile \"ok\""));
        let long = "a".repeat(65);
        let e = parse_err(&format!("[{long}]\ntype=\"api_token\"\naccount_id=\"x\"\n"));
        assert!(e.contains("1–64 characters"));
    }

    #[test]
    fn unknown_profile_lists_the_available_ones() {
        let config = Config::parse("[a]\ntype=\"api_token\"\naccount_id=\"x\"\n").unwrap();
        let e = config.profile("zzz").unwrap_err().to_string();
        assert!(e.contains("available profiles: a"));
        assert!(config
            .unknown(None)
            .to_string()
            .contains("CF_VAULT_PROFILE"));
    }

    #[test]
    fn the_old_token_type_name_points_at_the_new_one() {
        let e = parse_err("[a]\ntype=\"token\"\naccount_id=\"x\"\n");
        assert!(e.contains("renamed to \"api_token\""), "{e}");
        let e = parse_err("[a]\ntype=\"nope\"\naccount_id=\"x\"\n");
        assert!(e.contains("expected \"oauth2\" or \"api_token\""), "{e}");
    }

    #[test]
    fn a_profile_with_oauth_table_but_token_type_is_rejected() {
        let e =
            parse_err("[a]\ntype=\"api_token\"\naccount_id=\"x\"\n[a.oauth2]\nclient_id=\"c\"\n");
        assert!(e.contains("only valid for type = \"oauth2\""));
    }

    #[test]
    fn missing_file_names_the_expected_path() {
        let e = Config::load(Path::new("/definitely/not/here.toml"))
            .unwrap_err()
            .to_string();
        assert!(e.contains("/definitely/not/here.toml"));
    }
}
