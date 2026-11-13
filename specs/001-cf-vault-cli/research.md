# Research: cf-vault CLI

**Date**: 2026-11-13 | **Spec**: [spec.md](spec.md)

Sources: Cloudflare docs
([create an OAuth client](https://developers.cloudflare.com/fundamentals/oauth/create-an-oauth-client/),
[R2 temporary credentials](https://developers.cloudflare.com/r2/examples/authenticate-r2-temp-credentials/)),
a [third-party integration write-up](https://www.ubitools.com/cloudflare-oauth-client/) for
endpoint paths (not official), and the `cf-contrib/cloudflare-sts` repository
(`crates/cloudflare-sts-sdk/openapi/sts/v1/stsv1.tsp`, `crates/cloudflare-sts-api/README.md`,
`crates/cloudflare-sts-cli/README.md`).

Nothing below was verified against a live Cloudflare account. Items that need that are collected
as **spikes** (S1–S4) with a fallback, so planning does not depend on unverified behaviour.

## R1. Cloudflare's direct OAuth flow (spec open dependency)

**Findings (documented)**

- Third-party clients are supported with Authorization Code only. Public clients (CLI/desktop) use
  PKCE `S256` and token endpoint auth `none`; no client secret is needed. Client Credentials,
  Implicit, Password, and Device flows are not available to self-managed clients.
- Clients are registered per account (dashboard "OAuth clients", or
  `POST /accounts/{id}/oauth_clients` with an `OAuth Clients Write` token). They are **private by
  default**: only members of the owning account can authorize. Making a client public is
  permanent and needs a name, logo, client URL, a non-identity scope, and DNS TXT domain
  verification.
- Endpoints (from a third-party write-up, to be confirmed through discovery at
  `https://dash.cloudflare.com/.well-known/openid-configuration`): `/oauth2/auth`, `/oauth2/token`,
  `/oauth2/revoke`.
- Refresh tokens need the `refresh_token` grant on the client and `offline_access` in the
  requested scopes. Scope names are dot-delimited (`account.read`); they map to API token
  permission names; `GET /oauth/scopes` is the source of truth.
- Loopback redirect `http://127.0.0.1:<port>/callback` is accepted for CLI apps; matching is
  exact, so the port is fixed per registration.
- Wrangler's own client is Cloudflare-owned and "may use additional flows"; it MUST NOT be reused
  (per spec).

**Confirmed from the public discovery document** (`GET https://dash.cloudflare.com/.well-known/openid-configuration`, no credentials, 2026-11-13): issuer `https://dash.cloudflare.com`; endpoints `/oauth2/auth`, `/oauth2/token`, `/oauth2/revoke`; `code_challenge_methods_supported` includes `S256`; `token_endpoint_auth_methods_supported` includes `none` (public clients); `grant_types_supported` includes `authorization_code` and `refresh_token`; `scopes_supported` is only `openid`, `offline_access`, `offline`, so API scopes come from the client's registration (spike S2). cf-vault's discovery accepts this document and builds a valid authorization URL with `scope=openid offline_access` (checked by running `login --no-browser` with an unregistered client id and not opening the URL).

**Confirmed live against a Cloudflare Access for SaaS OIDC app** (2026-11-13, a real sign-in by the maintainer; no token values recorded): the authorization code flow with PKCE and the loopback redirect completes and cf-vault stores the session in the macOS Keychain; Access issues an access token, an ID token (300 s, claims `amr aud email exp iat iss jti sub`, audience the client id) and, when `offline_access` is requested, a refresh token; a refresh inside cf-vault's 120 s margin succeeded, **rotated the refresh token** and the new one was saved (persist-before-use holds); Access has no revocation endpoint. Access does not list `offline_access` in `scopes_supported`, so the profile must request it. This confirms the OIDC/refresh machinery (S3 for Access), not Cloudflare's own `dash.cloudflare.com` flow.

**Confirmed live against a deployed `cloudflare-sts` broker** (2026-11-13, the maintainer's own, with an Access for SaaS sign-in as the provider): the broker's metadata passed cf-vault's checks (issuer equals the URL, endpoints on its own host, one identity provider matching the sign-in's issuer and client); an exchange with a one-minute `--ttl` returned a Cloudflare API token and temporary R2 credentials for the profile's bucket; the command received `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and the `CLOUDFLARE_R2_*` variables; the token verified as `active` against the Cloudflare API from inside the command; the token was released through the broker's revocation endpoint when the command exited. The ID token was refreshed automatically before the exchange. This closes the "second broker" doubt about the mock only in part: it is the same broker the contract comes from, not a different implementation (SC-009).

**Confirmed live with a real tool** (2026-11-13, OpenTofu `plan` of the maintainer's infrastructure repo under `cf-vault exec -p <profile> --ttl 30m`): the state was read from the R2 backend through a `credential_process` helper fed by `CLOUDFLARE_R2_*`; the Cloudflare provider refreshed zone, Worker, R2, Access and zone-setting resources with the brokered token (the Cloudflare part of the plan was `0 to add, 0 to change, 0 to destroy`); the broker token was released when the command exited. The run's only errors came from other providers' own credentials (a GitHub token missing a scope, empty Tailscale credentials), which cf-vault neither sets nor removes: `AWS_*` and everything but `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_R2_*` / `CLOUDFLARE_ACCOUNT_ID` pass through untouched.

**Not documented (spikes)**

- **S1**: Does an OAuth access token work as `Authorization: Bearer` against
  `api.cloudflare.com/client/v4`, and therefore as `CLOUDFLARE_API_TOKEN` for Terraform and
  Wrangler?
- **S2**: Which scopes cover the calls cf-vault's users need (Workers, DNS, R2, token management),
  and does any scope let an OAuth session mint an API token or act as an R2 parent?
- **S3**: Access and refresh token lifetimes, and whether refresh tokens rotate (drives the
  refresh locking in R6).
- **S4**: Does `localhost`/`127.0.0.1` with a fixed port register successfully on a public client?

**Decision**

- Treat Cloudflare as one more OIDC-style provider (issuer `https://dash.cloudflare.com`) behind a
  single provider abstraction. The "no `oauth2`, no `exchange`" profile uses it with a client ID
  that **this project registers and publishes** (release gate, below).
- Until a client is registered and S1–S4 pass, the built-in client ID is empty and such a profile
  fails with a clear message pointing at `oauth2.client_id` (the user's own registered client) or
  a static-token profile. The code path is built and tested against a mock provider so it works
  as soon as a client exists.
- Deliver the access token unchanged as `CLOUDFLARE_API_TOKEN` (also the behaviour the spec
  requires for `oauth2` alone: no assumption that arbitrary provider tokens are accepted).
- **Release gate**: v1.0 MUST NOT advertise zero-configuration `personal` profiles until S1–S4 are
  confirmed and a public client is registered. If they fail, the spec's FR-003 first bullet is
  amended (fallback: static token or broker).

**Alternatives considered**: reuse Wrangler's client ID (rejected by the spec, and ToS risk);
require every user to register their own client (kept as the explicit `oauth2.client_id` path,
but too heavy as the default); Cloudflare Access for SaaS OIDC as the default (it is the broker's
people path, not Cloudflare API sign-in).

## R2 (R2). Temporary R2 credentials without a broker

**Findings**

- `POST /accounts/{account_id}/r2/temp-access-credentials` takes `bucket`, `parentAccessKeyId`,
  `permission` (`admin-read-write`, `admin-read-only`, `object-read-write`, `object-read-only`),
  `ttlSeconds` (max 604800), and optional `prefixes`/`objects`. It returns an access key ID,
  secret, and session token.
- The parent is an API token: the access key ID is the token's ID and the secret is the SHA-256
  of the token value. Community and `cloudflare-sts` notes: the token needs an R2 permission
  (Workers R2 Storage Write is known to work), otherwise error code `10000`. Credentials cannot
  be revoked early.
- An OAuth session has no token ID, so it has no obvious "parent access key".

**Decision**

- Direct derivation (no broker) supports **static-token profiles** as the parent. The token ID is
  read from Cloudflare's token-verify endpoint at derive time; the secret is computed locally.
  Nothing extra is stored.
- For OAuth-direct profiles, direct derivation is **spike S2-gated**: if an OAuth session can act
  as parent, it is enabled; otherwise a profile with `r2` and no broker is rejected at config
  validation with an explanation. This narrows spec FR-015 and will be fed back to the spec once
  S2 is known.
- Default `permission = "object-read-write"`, default TTL 15 minutes (900 s), overridable by `--ttl`; one
  bucket per profile (matches the broker and the single set of exported variables); `prefixes` supported (optional) because Cloudflare supports them.
- The R2 endpoint is `https://<account_id>.r2.cloudflarestorage.com` (jurisdiction buckets are out
  of scope and documented).

**Alternatives considered**: always derive S3 keys directly from the token (token ID +
SHA-256) with no temp credentials (rejected: long-lived, full-bucket parent secret in the child's
environment); require a broker for all R2 (rejected: spec User Story 4).

## R3. Broker contract (`cloudflare-sts`)

**Findings** (from TypeSpec `stsv1.tsp`)

- Exchange: `POST {url}/oauth/token`, `application/x-www-form-urlencoded`, body at most 16 KiB.
  Fields: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token`,
  `subject_token_type` (`…:id_token` or `…:jwt`), optional `audience` (default
  `https://api.cloudflare.com`), `requested_token_type`, `profile`, `ttl`.
- Response: `access_token?`, `issued_token_type`, `token_type` (`Bearer` or `N_A`), `expires_in`,
  `expires_at`, `token_id?`, `account_id?`, `profile`, `bucket?` (`name`, `access_key_id`,
  `secret_access_key`, `session_token`, `prefixes`, `endpoint`, `expires_on`).
- Errors: OAuth errors (RFC 6749 §5.2): `invalid_request`, `invalid_target`,
  `unsupported_grant_type`, `server_error`, `temporarily_unavailable` (400/500/503).
- Revoke: `POST {url}/oauth/revoke` with `token` (RFC 7009); always `200`.
- Discovery: `GET {url}/.well-known/oauth-authorization-server` (RFC 8414) with the broker
  extension `identity_providers: [{name, issuer, client_id}]`. Callers do not authenticate as
  clients. One profile yields one bucket; a profile may have a token, a bucket, or both.

**Decision**

- Implement the exact request/response shapes above as a small hand-written client (no generated
  code), tolerant of unknown response fields.
- Add an optional `oauth2.exchange.provider` (broker's provider name) for the case where the
  broker lists several identity providers; if ambiguous and unset, fail listing the names.
- The identity token sent is the user's **ID token** (`subject_token_type` id_token).
- `ttl` is sent only when the user passes `--ttl`.

## R4. Language, boilerplate, and dependencies (constitution XI)

**Decision**: implement in **Rust**, bootstrapped from `nixos-contrib/nix-vault` (same
constitution, same shape of problem: sign in, store in the keyring, run a child with credentials).
Rust version, edition, formatting, Nix flake packaging, and the integration-test harness are
copied from it. The dependency set is the subset of nix-vault's already-reviewed crates that
cf-vault needs; see [plan.md](plan.md#reuse-from-nix-vault) for the file-by-file reuse map.

| Need | Crate | Why |
|------|-------|-----|
| CLI | `clap` 4 (derive, env) | As nix-vault. |
| Config | `toml` 1, `serde`, `serde_path_to_error` | Strict decoding with key-level errors, as nix-vault. |
| OAuth 2.0 + PKCE, HTTP | `oauth2` 5 (blocking, rustls) and its re-exported `reqwest` 0.12 | PKCE and refresh already used by nix-vault; one `reqwest` for the broker and Cloudflare API too. |
| Credential store | `keyring-core` 1 + `apple-native-keyring-store`, `zbus-secret-service-keyring-store` | As nix-vault. |
| Secrets in memory | `secrecy` 0.10 and the `Secret` wrapper | As nix-vault. |
| Refresh lock | `fd-lock` 4 | As nix-vault. |
| Signals, exit codes | `signal-hook` 0.4, `libc` | As nix-vault `exec`. |
| Hidden prompt, browser | `rpassword` 7, `webbrowser` 1 | As nix-vault. |
| R2 parent secret | `sha2` | SHA-256 of the token value; no custom cryptography. |
| Time | `time` 0.3 | As nix-vault. |

Dropped from nix-vault: `age` and the encrypted-file store (the noninteractive environment path
covers CI), `tiny_http` if the proxy removal leaves it unused.

**V1 (resolved by design, confirm in implementation)**: the macOS store here is
`apple-native-keyring-store`, which talks to the Security framework directly, so secrets are not
passed on a `security` command line (constitution IV). The first implementation task checks this
by inspecting the crate and testing with a process-argument scan.

**Alternatives considered**: a Go implementation (the first draft of this plan), rejected in
favour of reusing a working, constitution-aligned codebase; hand-rolled OIDC/HTTP (rejected, more
code to audit); keeping the encrypted-file store (deferred, not required by any user story).

## R5. Credential storage layout

**Decision**: one keychain item per profile, service `cf-vault`, account = profile name, value =
JSON session (see [data-model.md](data-model.md)). Nothing secret on disk. The only files are the
user's config (no secrets) and a per-profile lock file (empty). If the store is unreachable or
missing, `login` and any command needing it fail with a clear error (constitution III); there is
no plaintext fallback flag in v1.

## R6. Refresh, concurrency, and rotation

**Decision**: serialize refresh per profile with an advisory file lock
(`$XDG_STATE_HOME/cf-vault/<profile>.lock`, owner-only, no content; `fd-lock`, as nix-vault's
`locker.rs`). Under the lock: re-read the
session, refresh if still expired, write back, release. This covers two simultaneous `exec` runs
(spec edge case) and is required if S3 shows refresh-token rotation. A rotated refresh token is persisted before the new access token is used (nix-vault's
behaviour). Refresh starts 120 seconds before expiry (nix-vault's margin); a refresh that fails with an auth error clears nothing and tells the user to
`login` again.

## R7. Process execution and signals

**Decision**: child launched with `std::process::Command`, stdin/stdout/stderr inherited, using the signal handling already in nix-vault's `exec.rs`, environment built from
the parent's with managed variables replaced or removed. `SIGINT` reaches the child through the
terminal; `SIGTERM`/`SIGHUP` are forwarded; cf-vault waits, then revokes broker tokens, then
exits with the child's code (`128+n` for a signal, `127` if not found). `SIGKILL` cannot be
caught: TTL is the backstop (documented limitation, FR-028).

Managed variables are always replaced or **removed** when not granted: `CLOUDFLARE_API_TOKEN`,
`CLOUDFLARE_R2_*`, plus `CLOUDFLARE_ACCOUNT_ID` (set from the profile). AWS variables are never touched
(no `--r2-env` option; Terraform's S3 backend uses a `credential_process` helper that reads
`CLOUDFLARE_R2_*`).

## R8. Noninteractive mode

**Decision**: noninteractive = standard input is not a terminal (clarified in the spec).
Credential precedence in noninteractive mode: `CF_VAULT_ID_TOKEN` (for broker profiles) →
`CLOUDFLARE_API_TOKEN` (static) → fail fast. Nothing is read from or written to the credential
store in this mode. In an interactive session an inherited `CLOUDFLARE_API_TOKEN` is replaced with
a one-line stderr notice (spec clarification).

## R9. Redaction

**Decision**: nix-vault's `Secret` type (`auth/redact.rs`) wraps every secret; its `Debug`/`Display`
render `[REDACTED]` and errors never carry values. HTTP bodies are never
logged. Tests grep all outputs for sentinel fake secrets (SC-004).
