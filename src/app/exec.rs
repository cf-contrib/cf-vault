//! `exec`: obtain credentials, put them in the child's environment only, run it, release them.
//!
//! The child runner follows nix-vault's `exec` (MIT): signals are forwarded, the exit status is
//! mirrored, and cleanup happens whatever the child did.

use std::{
    collections::BTreeSet,
    process::{Command, ExitStatus},
    sync::{
        atomic::{AtomicI32, Ordering},
        Arc,
    },
    time::Duration,
};

use crate::{
    app::{args::ExecCommandArgs, say, select, show_time, warn},
    vault::{
        auth::{self, env, redact::Secret, sts},
        cloudflare::{
            creds::{CredentialSet, Revocation},
            r2,
        },
        config::{Config, Kind, Profile},
        store::{CredentialStore, SessionKind},
        Error, Result,
    },
};
use signal_hook::{
    consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2},
    iterator::Signals,
    low_level,
};

/// Variables cf-vault manages: set when granted, removed from the child's environment when not.
const API_TOKEN: &str = "CLOUDFLARE_API_TOKEN";
const ACCOUNT_ID: &str = "CLOUDFLARE_ACCOUNT_ID";
const R2_PREFIX: &str = "CLOUDFLARE_R2_";

/// How the child's environment differs from the parent's.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct EnvPlan {
    /// Variables to remove (inherited values that are not granted).
    pub remove: BTreeSet<String>,
    /// Variables to set.
    pub set: Vec<(String, String)>,
}

/// Plans the child's environment from `credentials` and the names present in the parent's.
/// `AWS_*` variables are never touched.
pub fn plan_env(credentials: &CredentialSet, inherited: impl Iterator<Item = String>) -> EnvPlan {
    let mut plan = EnvPlan::default();
    plan.remove.insert(API_TOKEN.to_string());
    for name in inherited {
        if name.starts_with(R2_PREFIX) {
            plan.remove.insert(name);
        }
    }
    if let Some(token) = &credentials.api_token {
        plan.set
            .push((API_TOKEN.to_string(), token.expose().to_string()));
    }
    plan.set
        .push((ACCOUNT_ID.to_string(), credentials.account_id.clone()));
    if let Some(r2) = &credentials.r2 {
        plan.set.extend([
            (
                format!("{R2_PREFIX}ACCESS_KEY_ID"),
                r2.access_key_id.expose().to_string(),
            ),
            (
                format!("{R2_PREFIX}SECRET_ACCESS_KEY"),
                r2.secret_access_key.expose().to_string(),
            ),
            (
                format!("{R2_PREFIX}SESSION_TOKEN"),
                r2.session_token.expose().to_string(),
            ),
            (format!("{R2_PREFIX}ENDPOINT"), r2.endpoint.clone()),
            (format!("{R2_PREFIX}BUCKET"), r2.bucket.clone()),
        ]);
    }
    // What is set is not also removed
    for (name, _) in &plan.set {
        plan.remove.remove(name);
    }
    plan
}

/// The `exec` command.
pub struct ExecCommand {
    /// The validated configuration.
    pub config: Config,
    /// Where sessions are kept.
    pub store: CredentialStore,
    /// True when standard input is a terminal.
    pub interactive: bool,
}

impl ExecCommand {
    /// Runs the command and returns the child's exit status.
    pub fn execute(&mut self, args: &ExecCommandArgs) -> Result<ExitStatus> {
        let profile = select(&self.config, args.profile.profile.as_deref())?.clone();
        let quiet = args.parent.quiet;
        let ttl = args.ttl.as_ref();

        let mut credentials = self.credentials(&profile, args)?;

        // Without a broker, R2 credentials come from the profile's token: an API token is the
        // parent itself; for an OAuth session, a short-lived token is minted as the parent
        if let Some(r2_settings) = &profile.r2 {
            let token = credentials
                .api_token
                .clone()
                .expect("a profile without a broker always has a token");
            let lifetime = ttl
                .map(|t| Duration::from_secs(t.secs))
                .unwrap_or(r2::DEFAULT_TTL);
            let r2 = match profile.kind {
                Kind::ApiToken => r2::derive(&profile.account_id, &token, r2_settings, lifetime)?,
                Kind::OAuth2(_) => {
                    r2::derive_minting(&profile.account_id, &token, r2_settings, lifetime)?
                }
            };
            credentials.expires_at = credentials
                .earliest(credentials.expires_at)
                .or(r2.expires_at);
            credentials.r2 = Some(r2);
        }

        if self.interactive && std::env::var_os(API_TOKEN).is_some() {
            say(format!(
                "overriding {API_TOKEN} from the environment with profile \"{}\"",
                profile.name
            ));
        }
        if !quiet {
            summary(&profile, &credentials);
        }

        let plan = plan_env(
            &credentials,
            std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()),
        );
        let status = run_child(&args.command, &plan);
        release(&credentials, quiet);
        status
    }

    /// Obtains the credential set for the profile: from the environment when there is no
    /// terminal (or, for broker profiles, whenever an identity token is supplied), else from the
    /// stored session.
    fn credentials(&self, profile: &Profile, args: &ExecCommandArgs) -> Result<CredentialSet> {
        let ttl = args.ttl.as_ref().map(|t| t.text.as_str());
        if let Some(exchange_settings) = profile.exchange() {
            if let Some(id_token) = env::id_token() {
                return exchange_credentials(profile, exchange_settings, &id_token, ttl);
            }
        }
        if !self.interactive {
            return match (profile.exchange(), env::api_token()) {
                (None, Some(token)) => Ok(CredentialSet::token(&profile.account_id, token, None)),
                (Some(_), _) => Err(Error::Auth(format!(
                    "profile \"{}\" exchanges an identity token at a broker; without a terminal \
                     supply it in {}",
                    profile.name,
                    env::ID_TOKEN
                ))),
                (None, None) => Err(Error::Auth(format!(
                    "no terminal and no credentials for profile \"{}\"; supply {} (or run \
                     cf-vault login -p {} from a terminal)",
                    profile.name,
                    env::API_TOKEN,
                    profile.name
                ))),
            };
        }
        match &profile.kind {
            Kind::ApiToken => {
                let session = self
                    .store
                    .load(&profile.name)?
                    .filter(|s| s.kind == SessionKind::Token);
                let session = session.ok_or_else(|| Error::NoCredentials {
                    profile: profile.name.clone(),
                    detail: None,
                })?;
                Ok(CredentialSet::token(
                    &profile.account_id,
                    session.access_token,
                    None,
                ))
            }
            Kind::OAuth2(oauth) => {
                let session = auth::refresh_profile(profile, &self.store, &args.parent.state_dir)?;
                match &oauth.exchange {
                    Some(settings) => {
                        let id_token = session.id_token.ok_or_else(|| Error::NoCredentials {
                            profile: profile.name.clone(),
                            detail: Some("the stored session has no ID token".into()),
                        })?;
                        exchange_credentials(profile, settings, &id_token, ttl)
                    }
                    None => Ok(CredentialSet::token(
                        &profile.account_id,
                        session.access_token,
                        session.expires_at,
                    )),
                }
            }
        }
    }
}

/// Exchanges the identity token at the broker and checks the account it answers for.
fn exchange_credentials(
    profile: &Profile,
    settings: &crate::vault::config::Exchange,
    id_token: &Secret,
    ttl: Option<&str>,
) -> Result<CredentialSet> {
    let metadata = sts::discover(settings, false)?;
    let issued = sts::exchange(&metadata, id_token, settings, ttl)?;
    // A broker without a revocation endpoint cannot release the token: it expires on its own
    let revocation = issued
        .access_token
        .clone()
        .zip(metadata.revocation_endpoint.clone())
        .map(|(token, endpoint)| Revocation { endpoint, token });
    if let Some(account) = &issued.account_id {
        if account != &profile.account_id {
            // Release what was issued before refusing to use it
            if let Some(revocation) = &revocation {
                let _ = sts::revoke(&revocation.endpoint, &revocation.token);
            }
            return Err(Error::Exchange(format!(
                "the broker issued credentials for account {account}, but profile \"{}\" is \
                 for account {}; nothing was started",
                profile.name, profile.account_id
            )));
        }
    }
    Ok(CredentialSet {
        api_token: issued.access_token,
        api_token_id: issued.token_id,
        account_id: profile.account_id.clone(),
        r2: issued.r2_credentials,
        expires_at: issued.expires_at,
        revocation,
    })
}

fn summary(profile: &Profile, credentials: &CredentialSet) {
    match credentials.expires_at {
        Some(expires) => say(format!(
            "profile {} (expires {})",
            profile.name,
            show_time(expires)
        )),
        None => say(format!("profile {}", profile.name)),
    }
    if let Some(r2) = &credentials.r2 {
        let expiry = r2
            .expires_at
            .map(|t| format!(" at {}", show_time(t)))
            .unwrap_or_default();
        let prefixes = if r2.prefixes.is_empty() {
            String::new()
        } else {
            format!(" (prefixes {})", r2.prefixes.join(", "))
        };
        say(format!(
            "R2 temporary credentials for bucket {}{prefixes} can't be revoked; they expire{expiry}",
            r2.bucket
        ));
    }
}

/// Releases a broker-issued token after the command exited. A failure is a warning only.
fn release(credentials: &CredentialSet, quiet: bool) {
    let Some(revocation) = &credentials.revocation else {
        return;
    };
    match sts::revoke(&revocation.endpoint, &revocation.token) {
        Ok(()) => {
            if !quiet {
                let id = credentials
                    .api_token_id
                    .as_deref()
                    .map(|id| format!(" {}…", id.chars().take(4).collect::<String>()))
                    .unwrap_or_default();
                say(format!("released token{id}"));
            }
        }
        Err(e) => warn(format!(
            "the token was not released ({e}); it expires on its own"
        )),
    }
}

fn forward(pid: i32, signal: i32) {
    // SAFETY: plain kill(2) on the child's pid
    unsafe {
        libc::kill(pid, signal);
    }
}

/// Starts the child with the planned environment, forwards termination signals and mirrors its
/// exit status.
fn run_child(command: &[String], plan: &EnvPlan) -> Result<ExitStatus> {
    // The terminal sends Ctrl-C and Ctrl-\ to the child too; cf-vault just keeps waiting.
    // Handlers (unlike "ignore") are reset in the child on exec.
    // SAFETY: the closures do nothing, which is async-signal-safe
    let ids = unsafe {
        [
            low_level::register(SIGINT, || {}),
            low_level::register(SIGQUIT, || {}),
        ]
    };
    let mut signals = Signals::new([SIGTERM, SIGHUP, SIGUSR1, SIGUSR2])
        .map_err(|e| Error::io("cannot install signal handlers", e))?;
    let handle = signals.handle();
    let pid = Arc::new(AtomicI32::new(0));
    let pending = Arc::new(AtomicI32::new(0));
    let forwarder = {
        let (pid, pending) = (pid.clone(), pending.clone());
        std::thread::spawn(move || {
            for signal in signals.forever() {
                match pid.load(Ordering::SeqCst) {
                    0 => pending.store(signal, Ordering::SeqCst),
                    pid => forward(pid, signal),
                }
            }
        })
    };

    let mut child_command = Command::new(&command[0]);
    child_command.args(&command[1..]);
    for name in &plan.remove {
        child_command.env_remove(name);
    }
    child_command.envs(plan.set.iter().map(|(k, v)| (k, v)));
    let spawned = child_command.spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(e) => {
            handle.close();
            let _ = forwarder.join();
            return Err(Error::Spawn {
                command: command[0].clone(),
                not_executable: e.kind() == std::io::ErrorKind::PermissionDenied,
            });
        }
    };
    pid.store(child.id() as i32, Ordering::SeqCst);
    let early = pending.load(Ordering::SeqCst);
    if early != 0 {
        forward(child.id() as i32, early);
    }

    let status = child.wait();
    handle.close();
    let _ = forwarder.join();
    for id in ids.into_iter().flatten() {
        low_level::unregister(id);
    }
    status.map_err(|e| Error::io("cannot wait for the command", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::cloudflare::creds::R2Credentials;

    fn names(items: &[&str]) -> impl Iterator<Item = String> {
        items
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn plan_sets_what_is_granted_and_removes_the_rest() {
        let set = CredentialSet::token("acc", Secret::new("tok"), None);
        let plan = plan_env(
            &set,
            names(&[
                "CLOUDFLARE_R2_SESSION_TOKEN",
                "PATH",
                "AWS_ACCESS_KEY_ID",
                "CLOUDFLARE_API_TOKEN",
            ]),
        );
        assert!(plan
            .set
            .contains(&("CLOUDFLARE_API_TOKEN".to_string(), "tok".to_string())));
        assert!(plan
            .set
            .contains(&("CLOUDFLARE_ACCOUNT_ID".to_string(), "acc".to_string())));
        assert!(plan.remove.contains("CLOUDFLARE_R2_SESSION_TOKEN"));
        // What is set is not also removed, and AWS_* is never touched
        assert!(!plan.remove.contains("CLOUDFLARE_API_TOKEN"));
        assert!(!plan.remove.iter().any(|n| n.starts_with("AWS_")));
    }

    #[test]
    fn plan_exports_r2_variables_only_with_r2_credentials() {
        let mut set = CredentialSet::token("acc", Secret::new("tok"), None);
        assert!(!plan_env(&set, names(&[]))
            .set
            .iter()
            .any(|(n, _)| n.contains("R2")));
        set.r2 = Some(R2Credentials {
            access_key_id: Secret::new("ak"),
            secret_access_key: Secret::new("sk"),
            session_token: Secret::new("st"),
            endpoint: "https://acc.r2.cloudflarestorage.com".into(),
            bucket: "tf-state".into(),
            prefixes: vec![],
            expires_at: None,
        });
        let plan = plan_env(&set, names(&["CLOUDFLARE_R2_BUCKET"]));
        let set_names: Vec<_> = plan.set.iter().map(|(n, _)| n.as_str()).collect();
        for name in [
            "CLOUDFLARE_R2_ACCESS_KEY_ID",
            "CLOUDFLARE_R2_SECRET_ACCESS_KEY",
            "CLOUDFLARE_R2_SESSION_TOKEN",
            "CLOUDFLARE_R2_ENDPOINT",
            "CLOUDFLARE_R2_BUCKET",
        ] {
            assert!(set_names.contains(&name), "{name} not set");
        }
        assert!(plan.remove.is_empty() || !plan.remove.contains("CLOUDFLARE_R2_BUCKET"));
    }
}
