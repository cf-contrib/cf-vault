# Implementation Plan: cf-vault CLI

**Branch**: `001-cf-vault-cli` | **Date**: 2026-11-13 (revised: Rust, based on nix-vault) | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `/specs/001-cf-vault-cli/spec.md`

## Summary

`cf-vault` is a single-binary **Rust** CLI that signs a user in (OAuth 2.0 Authorization Code +
PKCE, or a static API token), keeps the session in the OS credential store, optionally exchanges
the user's identity token at an RFC 8693 broker (the existing `cloudflare-sts` contract),
optionally derives temporary R2 credentials, and runs a child process with the resulting
credentials in its environment only.

The project is bootstrapped from [`nixos-contrib/nix-vault`](../../../../nixos-contrib/nix-vault),
which already solves the hard shared parts in the same constitution-governed style: strict TOML
profiles, a redacting `Secret` type, keyring storage, a per-profile refresh lock, the PKCE
loopback sign-in, signal-forwarding `exec`, a Nix flake, and an integration-test harness with a
mock OAuth provider. cf-vault keeps those parts (adapted) and replaces the Nix-specific delivery
layer (netrc, `nix.conf` session, proxy) with Cloudflare environment-variable delivery, a broker
client, and R2 derivation. See "Reuse from nix-vault" below.

Research ([research.md](research.md)) established that Cloudflare supports third-party public
OAuth clients with PKCE and loopback redirects, but could not confirm from documentation that an
OAuth access token works as an API Bearer token, which scopes cover R2/token management, token
lifetimes, or that an OAuth session can serve as an R2 parent. These are tracked as spikes S1–S4
with explicit fallbacks, and the zero-configuration profile is a **release gate**, not an
assumption.

## Technical Context

**Language/Version**: Rust 1.95.0 (pinned in `rust-toolchain.toml`, as nix-vault), edition 2021,
`rustfmt.toml` copied from nix-vault.

**Primary Dependencies** (all already vetted in nix-vault; versions copied from its
`Cargo.toml`): `clap` 4 (derive, env, string); `toml` 1 + `serde` + `serde_json` +
`serde_path_to_error` (strict decoding with per-key errors); `oauth2` 5 with its re-exported
blocking `reqwest` 0.12 and rustls (also used for the broker and Cloudflare API calls, so only one
`reqwest` is built); `keyring-core` 1 with `apple-native-keyring-store` (macOS) and
`zbus-secret-service-keyring-store` (Linux); `secrecy` 0.10; `fd-lock` 4; `signal-hook` 0.4;
`libc`; `rpassword` 7; `sha2`; `time`; `webbrowser`. Dev: `assert_cmd`, `predicates`,
`expectrl`, `tempfile`.

**Dropped from nix-vault**: `age` and the encrypted-file store (not needed: CI uses the
noninteractive environment path; can be revisited), `tiny_http` if unused after the proxy is
removed, and all Nix/netrc/proxy code.

**Storage**: OS credential store, one JSON entry per profile (service `cf-vault`); user TOML
config (no secrets); empty per-profile lock files. No database, daemon, or server.

**Testing**: `cargo test` with `assert_cmd` integration tests against in-process loopback mocks
(OIDC provider reused from nix-vault's `tests/helpers/oauth.rs`; new mock broker and mock
Cloudflare API), an in-memory `SecretStore` for the store tier, and `expectrl` for the terminal
paths (hidden token prompt, interactive override notice). Fake credentials only (constitution IX).

**Target Platform**: macOS (arm64, amd64) and Linux (amd64, arm64), including headless Linux for
CI. Windows out of scope.

**Project Type**: CLI (single crate)

**Performance Goals**: `exec` with a valid, unexpired session adds under 1 second before the
command starts (SC-002); noninteractive failure within 5 seconds (SC-006).

**Constraints**: no plaintext fallback; no secrets in argv, logs, errors, or files; broker
contract reused as is; `unsafe` limited to what nix-vault's `exec` already needs (`libc` signal
and exit-status handling).

**Scale/Scope**: single user, tens of profiles, four commands, three network peers (identity
provider, broker, Cloudflare API).

## Constitution Check

*GATE: passed before Phase 0 research; re-checked after Phase 1 design.*

| Principle | Status | How the design satisfies it |
|-----------|--------|-----------------------------|
| I. Focused Scope | Pass | Only obtain, store, and deliver Cloudflare credentials. No server, no policy engine (the broker owns it). |
| II. Small, Explicit CLI | Pass | Four commands; each documents reads/writes/executes ([contracts/cli.md](contracts/cli.md)); stdout stable, errors on stderr. |
| III. Secure Persistent Storage | Pass | Keyring only; fails clearly if unavailable; the encrypted-file store is not carried over, so no alternative exists in v1. |
| IV. Secrets Never Leak | Pass | `Secret` (secrecy-based, redacting `Debug`/`Display`/serialization-to-output) reused from nix-vault; no HTTP bodies logged; tokens only via the child's environment. The macOS store uses the native Security framework, not the `security` CLI (V1 resolved by design; confirm in implementation). |
| V. Isolated Credential Sessions | Pass | Credentials live only in the child's environment; no shell/tool config edits; broker token revoked on exit. |
| VI. Respect User Configuration | Pass | Config is read-only for cf-vault; managed variables are replaced or removed, AWS variables never touched; conflicts (inherited token) reported. |
| VII. Separated Responsibilities | Pass | `auth`, `store`, `exchange`, `r2`, `config`, and `app` are separate modules behind small traits (`SecretStore`, a broker client, a provider); none depends on another's internals. |
| VIII. Cross-Platform Support | Pass | macOS and Linux behind the `store` trait and the loopback listener; Linux without a Secret Service uses the noninteractive path. |
| IX. Security-Focused Testing | Pass | Redaction, storage, lock, permission, and conflict tests following nix-vault's `redaction.rs` and `profile_changes.rs`; sentinel-secret scans; no real credentials. |
| X. Honest Documentation | Pass | README states: cleanup after `SIGKILL`, renewal during long commands, R2 credentials not revocable, spike-dependent profile caveats. |
| XI. Established Building Blocks | Pass | Only libraries already reviewed for nix-vault; no custom cryptography (SHA-256 for the R2 parent secret via `sha2`); additions justified in research R4. |

**Gate result**: no violations; Complexity Tracking is empty.

**Post-design re-check**: unchanged. The design adds no component beyond those above.

## Reuse from nix-vault

Copy into cf-vault and adapt (rename, change service name to `cf-vault`, env prefix to `CF_VAULT_`).
nix-vault is a sibling repository under the same governance, so no code is vendored by reference:
the files are copied once and then owned by cf-vault.

| nix-vault file | Use in cf-vault |
|----------------|-----------------|
| `Cargo.toml`, `rust-toolchain.toml`, `rustfmt.toml`, `flake.nix`, `flake.lock`, `LICENSE`, `NOTICE`, `CHANGELOG.md`, `scripts/` | Project scaffolding, Nix packaging, release metadata (`cargo binstall` block included). |
| `src/main.rs`, `src/app/args.rs`, `src/app/mod.rs` | Entry point and `clap` definitions, reduced to `login`, `logout`, `list`, `exec`. `-p`/`--profile` is kept but single-valued (nix-vault allows several on `exec`); `CF_VAULT_PROFILE` is the environment default. |
| `src/app/exec.rs` | Child process, signal forwarding, exit-code mapping, session lifecycle. Nix session/proxy parts removed; environment building replaced. |
| `src/vault/error.rs` | Error type with redaction. |
| `src/vault/config.rs` | Strict decoding, per-profile validation, secret-key rejection, error format. Keys and model replaced per [data-model.md](data-model.md). |
| `src/vault/auth/redact.rs`, `token.rs`, `code.rs` | `Secret`, `TokenSet`, discovery helpers, PKCE loopback sign-in (fixed `redirect_port`, default 8250, because Cloudflare matches redirect URIs exactly), refresh. |
| `src/vault/auth/env.rs` | Environment-supplied credentials (basis for `CLOUDFLARE_API_TOKEN` / `CF_VAULT_ID_TOKEN`). |
| `src/vault/auth/basic.rs` | Hidden-prompt flow, reused for the static token prompt. |
| `src/vault/store/{mod,keyring,locker}.rs` | `SecretStore` trait, keyring backend, per-profile lock for refresh. |
| `tests/helpers/{mod,oauth,vault}.rs` | Test harness and scripted mock OAuth provider. |
| `tests/integration/{redaction,refresh,login_oauth,login,logout,list,config,profile_changes,env_credentials}.rs` | Starting points for the equivalent cf-vault tests. |

Not reused: `src/vault/nix/*`, `auth/{device,process}.rs`, `store/file.rs`, `tests/integration/{nix_*,proxy,repo_and_cache}.rs`,
`tests/helpers/fake_nix.rs`, and the `age` dependency.

New code (no nix-vault equivalent): `exchange` (broker client), `r2` (temporary credentials),
the environment mapping and removal rules, the inherited-token override notice, and the
Cloudflare provider defaults.

## Project Structure

### Documentation (this feature)

```text
specs/001-cf-vault-cli/
├── plan.md              # This file
├── research.md          # Phase 0: decisions, spikes S1–S4
├── data-model.md        # Phase 1: profile, session, credential set, env mapping
├── quickstart.md        # Phase 1: runnable validation scenarios
├── contracts/
│   ├── cli.md           # Commands, flags, exit codes, environment contract
│   ├── config.md        # TOML schema and examples
│   └── broker.md        # cloudflare-sts contract as consumed
├── checklists/
│   └── requirements.md
└── tasks.md             # Phase 2 (/speckit-tasks, not created here)
```

### Source Code (repository root)

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
rustfmt.toml
flake.nix
flake.lock
CHANGELOG.md
LICENSE
NOTICE
README.md                    # Usage, configuration, honest limitations
config.example.toml
scripts/

src/
├── main.rs                  # Parse arguments, dispatch, map errors to exit codes
├── app/
│   ├── mod.rs
│   ├── args.rs              # clap: login, logout, list, exec
│   ├── login.rs
│   ├── logout.rs
│   ├── list.rs
│   └── exec.rs              # Resolve credentials, build env, run child, release token
└── vault/
    ├── mod.rs
    ├── error.rs
    ├── config.rs            # Profiles, strict decode, validation, resolution matrix
    ├── auth/
    │   ├── mod.rs           # Credential state, login, refresh under lock
    │   ├── code.rs          # Authorization Code + PKCE, loopback redirect
    │   ├── token.rs         # Token set, discovery, HTTP client
    │   ├── static_token.rs  # Hidden prompt for static API tokens
    │   ├── env.rs           # CF_VAULT_ID_TOKEN / CLOUDFLARE_API_TOKEN input
    │   └── redact.rs        # Secret type
    ├── exchange/
    │   └── mod.rs           # Broker: discovery, token exchange, revoke
    ├── r2/
    │   └── mod.rs           # Temporary R2 credentials from a static-token parent
    └── store/
        ├── mod.rs           # SecretStore trait, Session
        ├── keyring.rs
        └── locker.rs

tests/
├── integration.rs
├── integration/             # One file per behaviour (login, exec, exchange, r2, redaction, ...)
└── helpers/                 # mod.rs, oauth.rs (mock provider), broker.rs, cloudflare.rs, vault.rs
```

**Structure Decision**: a single crate with `src/app` (CLI wiring) and `src/vault` (domain),
mirroring nix-vault so changes can flow between the two projects. One module per responsibility
(constitution VII); traits are owned by the consumer so each piece is testable alone.

## Phases and Ordering Hints for Tasks

1. **Bootstrap**: copy and rename the scaffolding from nix-vault; strip Nix code; make
   `cargo build`, `cargo test`, and `nix build` pass on the trimmed crate.
2. **Config and profiles**: new model and resolution matrix on top of nix-vault's strict decoder.
3. **Static token path** (US3) to prove `exec` end to end: environment building and removal,
   `login`/`logout`/`list`.
4. **OAuth sign-in** (US1): adapt `code.rs` and refresh/locking; fixed redirect port.
5. **Broker** (US2): `exchange` client against the mock broker; revoke on exit.
6. **R2** (US4): `r2` module and the `CLOUDFLARE_R2_*` delivery.
7. **Noninteractive** (US5) and README limitations.
8. **Spikes S1–S4** run in parallel as soon as a registered client exists; they gate only the
   built-in Cloudflare client ID and the OAuth-direct R2 path, not the rest.

## Complexity Tracking

No constitution violations to justify.
