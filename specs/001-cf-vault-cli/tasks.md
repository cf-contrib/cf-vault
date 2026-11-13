---

description: "Task list for the cf-vault CLI"
---

# Tasks: cf-vault CLI

**Input**: Design documents from `/specs/001-cf-vault-cli/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/ (cli.md, config.md, broker.md), quickstart.md

**Tests**: Included. The constitution (Principle IX) requires automated tests for security-sensitive behaviour (storage, redaction, cleanup, permissions, conflicts) and user-visible workflows, using fake credentials and mock services only. Write each story's tests first and confirm they fail before implementing.

**Organization**: Grouped by user story (US1 to US6, in spec priority order) so each can be implemented and tested independently.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependency on an incomplete task)
- **[Story]**: US1 to US6, from spec.md
- Paths follow plan.md's tree, repository root `cf-vault/`. `NV` below means the sibling checkout `../../nixos-contrib/nix-vault` (relative to the repo root). Files are copied from it once and then owned by cf-vault; do not reference it at build time.

## Path Conventions

Single crate: `src/app/` (CLI wiring), `src/vault/` (domain), `tests/integration/`, `tests/helpers/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Bootstrap the crate from nix-vault with no Nix-specific code, building and testing clean.

- [X] T001 Copy project scaffolding from NV into the repo root and rename `nix-vault` to `cf-vault`: `Cargo.toml`, `rust-toolchain.toml` (channel 1.95.0), `rustfmt.toml`, `flake.nix`, `flake.lock`, `LICENSE`, `NOTICE`, `CHANGELOG.md`, `scripts/`. Update package name, description ("Manage Cloudflare credentials: sign in, store them in the system keychain, and run commands with them"), repository/homepage URLs (`cf-contrib/cf-vault`), the `cargo binstall` block, and the flake description, cachix settings and `mainProgram`.
- [X] T002 Edit dependencies in `Cargo.toml`: keep `clap`, `fd-lock`, `libc`, `oauth2` (reqwest-blocking, rustls-tls, using its re-exported `reqwest` for all HTTP), `keyring-core`, `rpassword`, `secrecy`, `serde`, `serde_json`, `serde_path_to_error`, `sha2`, `signal-hook`, `time`, `toml` (preserve_order), `webbrowser`, the macOS and Linux keyring store crates, and dev-dependencies `assert_cmd`, `expectrl`, `predicates`, `tempfile`; remove `age` and `tiny_http`. Add a non-default cargo feature `test-store` (see T014).
- [X] T003 [P] Add `.gitignore` (`/target`, `/result`) and `config.example.toml` containing the three example profiles from `contracts/config.md` (no secrets).
- [X] T004 Create the module skeleton as empty compiling modules per plan.md: `src/main.rs`, `src/app/{mod,args,login,logout,list,exec}.rs`, `src/vault/{mod,error,config}.rs`, `src/vault/auth/{mod,code,token,prompt,env,redact,sts}.rs`, `src/vault/cloudflare/{mod,credentials,r2}.rs`, `src/vault/store/{mod,keyring,locker}.rs`. `cargo build` must pass.
- [X] T005 [P] Copy and adapt the test harness from NV: `tests/integration.rs`, `tests/helpers/mod.rs`, `tests/helpers/oauth.rs` (scripted mock OAuth/OIDC provider on a loopback port), `tests/helpers/vault.rs` (temp config + isolated store + `assert_cmd` runner with `CF_VAULT_CONFIG`). Remove everything Nix-specific. `cargo test` must pass with zero tests.
- [X] T006 [P] Verify `rustfmt` and `clippy` pass on the skeleton (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`) and `nix build` produces a `cf-vault` binary on the host platform.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Config, secrets, storage, locking, error handling, and the child-process runner that every story uses.

**⚠️ CRITICAL**: No user story work can begin until this phase is complete.

### Tests for the foundation (write first, must fail)

- [X] T007 [P] Redaction test in `tests/integration/redaction.rs`: with sentinel secrets (e.g. `SENTINEL-SECRET-123`) fed through every failing path built so far, stdout and stderr contain no sentinel; `Debug`/`Display` of `Secret` renders `[REDACTED]`.
- [X] T008 [P] Config tests in `tests/integration/config.rs` covering every rule in the Profile table of `data-model.md`: name `1–64 chars of A-Za-z0-9_.-, starts alphanumeric`, unique; `type` is `oauth2` or `token` ("Unknown value is an error naming the profile"); `account_id` required; unknown keys rejected with the profile and key (never the value); secret-like keys (`token`, `secret`, `password`, `client_secret`, `refresh_*`) rejected with "use `cf-vault login`; secrets never go in config"; `issuer` requires `client_id` and the reverse; `issuer` is `https` only; `exchange.url` is `https` (loopback `http` allowed for tests); `exchange.profile` required; `r2` rejected together with `exchange`; `r2.bucket` is exactly one string (a list is rejected with "use one profile per bucket"); `r2.permission` is `object-read-write` (default) or `object-read-only`; all profile errors reported, not just the first.
- [X] T009 [P] Store tests in `tests/integration/storage.rs`: session round trip; a session whose `kind` does not match the profile `type` is treated as not signed in; the keyring being unavailable fails with a clear error and writes nothing to disk (Principle III); lock file and its directory are owner-only (0600 / 0700).

### Implementation

- [X] T010 [P] Copy `NV/src/vault/auth/redact.rs` to `src/vault/auth/redact.rs` (the `Secret` type; `Debug`/`Display` render `[REDACTED]`, serialization only into the store). Keep unit tests.
- [X] T011 [P] Copy `NV/src/vault/error.rs` to `src/vault/error.rs`; trim to cf-vault variants (config, auth, store, exchange, r2, io, usage). Errors never carry secret values. Map failures to exit code `1` and clap usage errors to `2`.
- [X] T012 Implement `src/vault/config.rs` (adapt `NV/src/vault/config.rs`): load from `--config`, else `CF_VAULT_CONFIG`, else `<os config dir>/cf-vault/config.toml`; top-level tables are profiles; strict decoding with `serde_path_to_error`; the keys and rules in `contracts/config.md` and the Profile table (`type`, `account_id`, `[p.oauth2]` `issuer`, `client_id`, `scopes` (defaults to `["openid"]` plus `offline_access` when the provider supports it), `redirect_port` (default 8250), `[p.oauth2.exchange]` `url`, `profile`, `provider`, `[p.r2]` `bucket`, `permission`, `prefixes`); expose the resolution matrix (Cloudflare default, exchange-only, provider-only, both); validate every profile and report all errors; missing file prints the expected path (depends on T008, T010, T011).
- [X] T013 Implement `src/vault/store/mod.rs`: the `SecretStore` trait (`get`, `set`, `delete`) and the `Session` JSON model from the Session table: `version` (int, starts at 1), `kind` (`oauth2`|`token`), `access_token`, `id_token?`, `refresh_token?`, `expires_at?`, `id_token_expires_at?`, `issuer?`, `client_id?`; service name `cf-vault`, account = profile name; one entry per profile (depends on T010).
- [X] T014 Add the test store in `src/vault/store/mod.rs` behind the non-default `test-store` feature: a file-backed `SecretStore` selected by `CF_VAULT_STORE_DIR`, compiled out of release builds and never selectable at runtime in a default build. Integration tests run with `--features test-store`; document this in `README.md` later (T062). Guard against leakage into releases: add a CI check (also run in T067) that the release binary and the `nix build` output are built without `test-store` and cannot read `CF_VAULT_STORE_DIR`. (depends on T013)
- [X] T015 [P] Implement `src/vault/store/keyring.rs` (adapt `NV/src/vault/store/keyring.rs`): `keyring-core` with `apple-native-keyring-store` on macOS and `zbus-secret-service-keyring-store` on Linux; fail with a clear error when no store is available, never fall back to plaintext. Confirm V1 in a test: the macOS path puts no secret in process arguments (depends on T013).
- [X] T016 [P] Implement `src/vault/store/locker.rs` (copy from `NV/src/vault/store/locker.rs`): per-profile advisory lock via `fd-lock` at `$XDG_STATE_HOME/cf-vault/<profile>.lock` (fallback `~/.local/state`), directory 0700, file 0600, no content.
- [X] T017 Define the in-memory `CredentialSet` in `src/vault/cloudflare/credentials.rs` per the Credential Set and R2Credentials tables: `api_token?` (secret), `api_token_id?`, `account_id`, `r2?` (`access_key_id`, `secret_access_key`, `session_token`, `endpoint`, `bucket`, `prefixes`, `expires_at`), `expires_at?`, and a `revoke` hook for broker tokens. Never persisted, never `Debug`-printable with values (depends on T010).
- [X] T018 Implement environment building in `src/app/exec.rs` as a pure function `build_env(parent, &CredentialSet) -> env`: set `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, and (R2 only) `CLOUDFLARE_R2_ACCESS_KEY_ID`, `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, `CLOUDFLARE_R2_SESSION_TOKEN`, `CLOUDFLARE_R2_ENDPOINT`, `CLOUDFLARE_R2_BUCKET`; remove inherited `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_R2_*` that are not granted; never set, change, or remove any `AWS_*` variable (depends on T017).
- [X] T019 Implement the child-process runner in `src/app/exec.rs` (adapt `NV/src/app/exec.rs`): inherit stdin/stdout/stderr, forward `SIGTERM`/`SIGHUP` with `signal-hook`, wait, return the child's exit code, `128+n` when killed by signal `n`, `127` when not found; run a release hook after the child exits without changing the exit code (depends on T018).
- [X] T020 [P] Implement `src/app/args.rs` with `clap` (adapt `NV/src/app/args.rs`): subcommands `login`, `logout`, `list`, `exec`; global `-q/--quiet`, `-v/--verbose`, `--config` (`CF_VAULT_CONFIG`); `-p/--profile <name>` on `login`, `logout`, `exec`, given exactly once (a second `-p` is a usage error, exit 2), default from `CF_VAULT_PROFILE`, flag wins over the environment, missing everywhere fails and lists configured profiles; `login --no-browser`; `exec --ttl <duration>` (minimum `1m`) and `-- <command> [args...]`.
- [X] T021 Wire `src/main.rs` and `src/app/mod.rs`: parse arguments, load config, dispatch, print errors to stderr, return exit codes from T011.

**Checkpoint**: `cargo test` passes for T007 to T009; foundation ready.

---

## Phase 3: User Story 1 - Run a command with Cloudflare credentials (Priority: P1) 🎯 MVP

**Goal**: Sign in once through the browser (Authorization Code + PKCE), store the session in the OS credential store, refresh automatically, and run a command with `CLOUDFLARE_API_TOKEN` set for its lifetime only; `logout` removes everything.

**Independent Test**: Quickstart scenario 1 against the mock OIDC provider: `login`, then `exec` prints a token the parent shell does not have; `logout` makes `exec` fail without starting the command.

### Tests for User Story 1 (write first, must fail)

- [X] T022 [P] [US1] `tests/integration/login_oauth.rs`: `login -p` with explicit `issuer` and `client_id` against the mock provider stores a session; `state` mismatch rejected; abandoned sign-in times out (300 s, shortened by test hook) leaving no partial session; busy `redirect_port` gives a clear error; `--no-browser` prints the authorization URL on stderr.
- [X] T023 [P] [US1] `tests/integration/exec_session.rs`: `exec -p` runs the command with `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`, returns the command's exit status unchanged, parent environment unmodified; unknown profile lists available profiles; no profile anywhere fails (exit 1); `-p` twice exits 2; `CF_VAULT_PROFILE` default and flag precedence (quickstart scenario 8); child runner (FR-017): `SIGTERM` and `SIGHUP` are forwarded to the command, a command killed by signal `n` gives exit code `128+n`, a missing command gives `127`, and standard input, output and error are inherited.
- [X] T024 [P] [US1] `tests/integration/refresh.rs`: expired access token with a refresh token is renewed without a browser; a rotated refresh token is persisted before the new access token is used; refresh rejected means the command is not started and the user is told to run `login` again; two simultaneous `exec` runs under the lock never corrupt the session; changed `issuer` or `client_id` makes the stored session stale.
- [X] T025 [P] [US1] `tests/integration/logout.rs`: `logout -p` deletes the stored session, succeeds when nothing is stored, revokes the refresh token at the provider on a best-effort basis (failure is a warning), and a later `exec` fails without starting the command.
- [X] T026 [P] [US1] `tests/integration/profile_changes.rs` (adapt NV's): the inherited-token override. In an interactive session (via `expectrl`) an inherited `CLOUDFLARE_API_TOKEN` is replaced by the profile's token and exactly one stderr notice `cf-vault: overriding CLOUDFLARE_API_TOKEN from the environment with profile "<name>"` appears without showing the value; stale `CLOUDFLARE_R2_*` are removed.
- [X] T027 [P] [US1] Extend `tests/integration/redaction.rs`: sentinel access, refresh and ID tokens never appear in stdout, stderr, `-v` output, error messages, or the config file after `login`, `exec`, and `logout`.

### Implementation for User Story 1

- [X] T028 [P] [US1] Implement `src/vault/auth/token.rs` (adapt `NV/src/vault/auth/token.rs`): `TokenSet`, the shared blocking HTTP client (oauth2's re-exported `reqwest`, rustls), OIDC discovery by one `GET <issuer>/.well-known/openid-configuration` (authorization, token, revocation endpoints; HTTPS only, loopback `http` allowed for tests).
- [X] T029 [US1] Implement `src/vault/auth/code.rs` (adapt `NV/src/vault/auth/code.rs`): Authorization Code + PKCE S256 with a loopback redirect `http://127.0.0.1:<redirect_port>/callback` (default 8250), `state` verified, 300 s timeout, `--no-browser` prints the URL, browser opened with `webbrowser`, authorization code never logged (depends on T028).
- [X] T030 [US1] Implement `src/vault/auth/mod.rs` (adapt `NV/src/vault/auth/mod.rs`): `CredentialState` (Absent, StaleIdentity, Usable, Expiring, Expired), `REFRESH_MARGIN` of 120 s, refresh under the T016 lock (re-read the session, refresh if still expired, persist the rotated refresh token before use, write back), refresh error tells the user to `login` again and clears nothing (depends on T013, T016, T028).
- [X] T031 [US1] Implement the provider resolution in `src/vault/config.rs`: no `oauth2` and no `exchange` means the Cloudflare provider (issuer `https://dash.cloudflare.com`) with a built-in client ID constant that is empty until a client is registered; while empty, such a profile fails with a message naming `oauth2.client_id` or a static-token profile (research R1, release gate T072). Provider-only profiles deliver the provider's access token unchanged (depends on T012, T028).
- [X] T032 [US1] Implement `src/app/login.rs`: `login -p` for `type = "oauth2"` runs `code.rs`, builds the `Session` (kind `oauth2`, issuer, client_id), replaces an existing session only after the new sign-in succeeds, exit 0 / 1 (depends on T029, T030, T031).
- [X] T033 [P] [US1] Implement `src/app/logout.rs`: delete the profile's store item; best-effort revoke of the refresh token at the provider's revocation endpoint; succeed if nothing stored (depends on T013, T028).
- [X] T034 [US1] Implement the oauth2 path in `src/app/exec.rs`: resolve the profile, obtain a usable session (refresh when `Expiring`/`Expired` per T030), build a `CredentialSet` with the access token and the profile's `account_id`, apply the interactive override notice (interactive means stdin is a terminal), run T019 (depends on T018, T019, T030, T032).
- [X] T035 [US1] Print the one-line stderr summary on `exec` (`cf-vault: profile <name> (expires <time>)`), never a secret; honour `-q`/`-v` (depends on T034).

**Checkpoint**: User Story 1 works end to end against the mock provider; MVP.

---

## Phase 4: User Story 2 - Short-lived, policy-scoped credentials through a broker (Priority: P2)

**Goal**: Exchange the user's ID token at an RFC 8693 broker (the existing `cloudflare-sts` contract) for a short-lived Cloudflare API token and optional R2 credentials; revoke after the command exits.

**Independent Test**: Quickstart scenario 2 against a mock broker: a profile with only an `exchange` section completes `login` and `exec`; the command gets the broker's token, the mock sees one exchange and one revoke, and nothing long-lived beyond the ID/refresh tokens is stored.

### Tests for User Story 2 (write first, must fail)

- [X] T036 [P] [US2] Create the mock broker in `tests/helpers/broker.rs` implementing `GET /.well-known/oauth-authorization-server` (with `identity_providers`), `POST /oauth/token`, `POST /oauth/revoke`, and the OAuth error shapes (`invalid_request`, `invalid_target`, `unsupported_grant_type`, `server_error`, `temporarily_unavailable`) from `contracts/broker.md`; it records requests so tests can assert on them.
- [X] T037 [P] [US2] `tests/integration/exchange.rs`: discovery picks the provider and client from broker metadata (exchange-only profile); several providers without `exchange.provider` fails listing the names; zero providers is an error; metadata `issuer` must equal the configured URL; the exchange request is form-encoded with `grant_type`, `subject_token`, `subject_token_type` (id_token), `profile`, and `ttl` only when `--ttl` is given; a response `account_id` that differs from the profile's `account_id` fails before the command starts, names the profile and both IDs, shows no credential, and revokes the issued token; the response `access_token` becomes `CLOUDFLARE_API_TOKEN`, `bucket` becomes the `CLOUDFLARE_R2_*` variables, bucket-only profiles (`token_type` `N_A`) omit the token; the stored ID token and refresh token never appear in the command's environment (FR-016).
- [X] T038 [P] [US2] `tests/integration/exchange_failures.rs`: a refused exchange (400 `invalid_request`) does not start the command, shows the broker's code and description and no credential text; `503` is retried once after one second and other errors are not; an unreachable broker never falls back to a weaker credential; revoke is called once after the command exits and a failing revoke is a warning that leaves the command's exit status unchanged; explicit provider plus `exchange` signs in at the configured provider and exchanges its ID token.

### Implementation for User Story 2

- [X] T039 [US2] Implement the broker client in `src/vault/auth/sts.rs` exactly per `contracts/broker.md`: discovery (HTTPS, same host endpoints, loopback `http` for tests), `exchange` with the field set above and no `audience` or `requested_token_type`, tolerant parsing that ignores unknown fields, retry-once on `503`, error mapping that never includes request bodies, `revoke` with `token` and `token_type_hint=access_token`; secrets held as `Secret` (depends on T010, T011).
- [X] T040 [US2] Extend `src/vault/config.rs` so `oauth2.exchange` resolves the identity provider: exchange-only discovers issuer and client from broker metadata (honouring `exchange.provider`), provider-plus-exchange uses the configured issuer and `client_id`; `exchange.url` is `https` (loopback `http` allowed for tests) and `exchange.profile` is "Required in v1"; `r2` on a profile with `exchange` is rejected (depends on T012, T039).
- [X] T041 [US2] Extend `src/app/login.rs` and `src/vault/auth/mod.rs` so exchange profiles store the ID token and `id_token_expires_at` in the session and refresh the ID token before expiry (depends on T032, T040).
- [X] T042 [US2] Add the exchange path to `src/app/exec.rs`: refresh the ID token if needed, call `exchange`, build the `CredentialSet` (token, `token_id`, R2 from `bucket`, `account_id`, earliest expiry), first comparing the response `account_id` with the profile's (mismatch: revoke the token and fail before starting the command), print the summary lines (`cf-vault: R2 temporary credentials can't be revoked; they expire at <time>` when R2 is issued), and register the revoke hook run after the child exits (depends on T034, T039, T041).
- [X] T043 [US2] Pass the parsed `--ttl` (defined and validated in T020, minimum `1m`) to the broker as `ttl` in `src/app/exec.rs`, only when given (depends on T042).

**Checkpoint**: User Stories 1 and 2 both work independently.

---

## Phase 5: User Story 3 - Static API token profiles (Priority: P2)

**Goal**: Store a Cloudflare API token under a `type = "token"` profile, never in the config file, and inject it like any other credential.

**Independent Test**: Quickstart scenario 3: `login -p` stores a fake token read without echo; `exec` delivers it as `CLOUDFLARE_API_TOKEN`; with the store unavailable `login` fails clearly and no file contains the token.

### Tests for User Story 3 (write first, must fail)

- [X] T044 [P] [US3] `tests/integration/login.rs` (adapt NV's): `login -p` for a `type = "token"` profile prompts without echo (via `expectrl`) and requires a terminal; the token lands in the store as a `Session` of kind `token`; an empty token is rejected; a secret-looking key in the config is refused.
- [X] T045 [P] [US3] `tests/integration/exec_static.rs`: `exec` delivers the stored token as `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID`; with the keyring unavailable `login` and `exec` fail with a clear error and no plaintext file exists anywhere under the home and temp directories (sentinel scan).

### Implementation for User Story 3

- [X] T046 [P] [US3] Implement `src/vault/auth/prompt.rs` (adapt `NV/src/vault/auth/basic.rs`): hidden prompt with `rpassword`, trims and validates non-empty, never echoes or logs the value (depends on T010).
- [X] T047 [US3] Extend `src/app/login.rs` for `type = "token"`: prompt, store a `Session` (kind `token`, no expiry), fail with a clear error when no secure store is available (Principle III) (depends on T013, T046).
- [X] T048 [US3] Add the static-token path to `src/app/exec.rs`: read the stored session, build the `CredentialSet` with `api_token` and `account_id`, no network call (depends on T034, T047).

**Checkpoint**: User Stories 1 to 3 work independently.

---

## Phase 6: User Story 4 - R2 credentials without a broker (Priority: P3)

**Goal**: Derive temporary R2 credentials from a stored static API token for one named bucket and deliver them as `CLOUDFLARE_R2_*`, never touching `AWS_*`.

**Independent Test**: Quickstart scenario 4 against a mock Cloudflare API: a static-token profile with `[x.r2] bucket="tf-state"` receives the R2 variables and a preset `AWS_ACCESS_KEY_ID` is unchanged; a profile without `r2` triggers no R2 request.

### Tests for User Story 4 (write first, must fail)

- [X] T049 [P] [US4] Create the mock Cloudflare API in `tests/helpers/cloudflare.rs`: token verify (returns the token ID) and `POST /accounts/{account_id}/r2/temp-access-credentials` (records `bucket`, `parentAccessKeyId`, `permission`, `ttlSeconds`, `prefixes`; returns access key, secret, session token; can return error code `10000`).
- [X] T050 [P] [US4] `tests/integration/r2.rs`: the request carries `parentAccessKeyId` equal to the token ID and `bucket` equal to the profile's single bucket; the secret is derived as the SHA-256 of the token value (no secret leaves the machine except the token itself as bearer); `permission` defaults to `object-read-write` and `object-read-only` is honoured; `ttlSeconds` defaults to 900 (15 minutes) and follows `--ttl`; `prefixes` are passed through; the child gets `CLOUDFLARE_R2_ACCESS_KEY_ID`, `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, `CLOUDFLARE_R2_SESSION_TOKEN`, `CLOUDFLARE_R2_ENDPOINT` (`https://<account_id>.r2.cloudflarestorage.com`), `CLOUDFLARE_R2_BUCKET`; the summary says the credentials can't be revoked; an error `10000` explains that the token needs an R2 permission.
- [X] T051 [P] [US4] `tests/integration/aws_untouched.rs`: with and without R2, preset `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` reach the child unchanged and none is added; a profile with no `r2` and no broker triggers no R2 request and sets no R2 variable; a profile of `type = "oauth2"` with `r2` and no `exchange` fails config validation with an explanation (direct R2 needs a static-token parent until spike S2 says otherwise).

### Implementation for User Story 4

- [X] T052 [US4] Implement `src/vault/cloudflare/r2.rs`: read the token ID from Cloudflare's token-verify endpoint (confirm the exact account-token verify path against the API docs during implementation), compute the parent secret with `sha2`, call temp-access-credentials with `bucket`, `parentAccessKeyId`, `permission`, `ttlSeconds`, `prefixes`, return `R2Credentials`; `ttlSeconds` is 900 (15 minutes) unless a `--ttl` value is passed in; map code `10000` to a clear message; never log bodies or secrets (depends on T017).
- [X] T053 [US4] Extend `src/vault/config.rs` validation for `[p.r2]`: `bucket` is "Exactly one bucket name (a valid R2 bucket name). Required when `r2` is present"; reject lists; allowed only on `type = "token"` profiles (`oauth2` without `exchange` rejected per T051); `permission` and `prefixes` rules per Profile table (depends on T012).
- [X] T054 [US4] Add the R2 step to the static-token path in `src/app/exec.rs`: when the profile has `r2`, derive credentials before launching (passing the parsed `--ttl`, else the 15-minute default) and merge into the `CredentialSet`; no `r2` means no request (depends on T048, T052, T053).

**Checkpoint**: User Stories 1 to 4 work independently.

---

## Phase 7: User Story 5 - Noninteractive CI/CD use (Priority: P3)

**Goal**: `exec` runs without a browser, keychain, or prompt using credentials from the environment, and fails fast when none are supplied.

**Independent Test**: Quickstart scenario 5 in a clean environment with stdin from `/dev/null`: a supplied token or ID token succeeds; nothing supplied fails within 5 seconds with a non-zero status; the store is never touched.

### Tests for User Story 5 (write first, must fail)

- [X] T055 [P] [US5] `tests/integration/env_credentials.rs` (adapt NV's): with stdin not a terminal, `CLOUDFLARE_API_TOKEN` supplies any profile without `exchange` (static-token and OAuth, delivered as is) and `CF_VAULT_ID_TOKEN` supplies an exchange profile (`CLOUDFLARE_API_TOKEN` alone is refused for it) (exchanged at the mock broker and revoked after); the store is never opened or written (asserted with an unavailable store); `CF_VAULT_ID_TOKEN` takes precedence over any stored session; nothing supplied exits non-zero within 5 seconds and never reads input.
- [X] T056 [P] [US5] Extend `tests/integration/exec_session.rs`: in noninteractive mode an inherited `CLOUDFLARE_API_TOKEN` is used as the credential (no override notice); in an interactive session it is replaced (covered by T026); no credential is persisted in noninteractive mode.

### Implementation for User Story 5

- [X] T057 [P] [US5] Implement `src/vault/auth/env.rs` (adapt `NV/src/vault/auth/env.rs`): read `CF_VAULT_ID_TOKEN` and `CLOUDFLARE_API_TOKEN` into `Secret`s; empty values count as unset.
- [X] T058 [US5] Add noninteractive handling to `src/app/exec.rs`: noninteractive when stdin is not a terminal; `CF_VAULT_ID_TOKEN` for exchange profiles, `CLOUDFLARE_API_TOKEN` for every other profile, else fail fast with an actionable message; skip the credential store entirely; do not persist anything (depends on T042, T048, T057).
- [X] T059 [US5] Make `login` refuse noninteractive use with a clear error (the browser flow and the hidden prompt both need a person) in `src/app/login.rs` (depends on T032, T047).

**Checkpoint**: User Stories 1 to 5 work independently.

---

## Phase 8: User Story 6 - Inspect profiles (Priority: P3)

**Goal**: `list` shows every profile with its type and session state, never a secret.

**Independent Test**: Quickstart scenario 6: with profiles in several states `list` and `list --json` show each state and contain no credential material.

### Tests for User Story 6 (write first, must fail)

- [X] T060 [P] [US6] `tests/integration/list.rs` (adapt NV's): states `signed in`, `expired`, `not signed in`, `static token`; `--json` matches `[{"profile","type","account_id","exchange","state"}]` and is stable; no secret or sentinel in output; missing config prints the expected path on stderr and exits 1.

### Implementation for User Story 6

- [X] T061 [US6] Implement `src/app/list.rs`: read config and, per profile, derive the state from the store item (expiry comparison only, never printing values); table by default, `--json` for scripts (depends on T013, T030).

**Checkpoint**: All user stories independently functional.

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Documentation, hygiene scans, and the live spikes that gate the zero-configuration profile.

- [X] T062 [P] Write `README.md`: usage per `contracts/cli.md`, configuration per `contracts/config.md`, the broker and Terraform `credential_process` setup (`tf-contrib/terraform-cloudflare-backend`), the `test-store` feature, and the known limitations required by FR-028 (cleanup after `SIGKILL`, renewal during long commands, R2 credentials cannot be revoked early, a `credential_process` helper does not pass expiry on so `--ttl` extends long runs).
- [X] T063 [P] Update `config.example.toml` and `CHANGELOG.md` for the final keys.
- [X] T064 [P] Add a repo-wide sentinel scan in `tests/integration/secret_hygiene.rs` (SC-004, SC-005): run login, exec, exchange, R2, and logout with sentinel secrets, then scan stdout, stderr, config, home and temp directories for any hit.
- [X] T065 [P] Add a permissions test in `tests/integration/permissions.rs`: lock files and directories are owner-only; no credential file or process outlives the child (Principle V).
- [X] T066 Run every scenario in `quickstart.md` (1 to 8) against the mocks and fix any discrepancy between the document and behaviour.
- [X] T067 Run `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --features test-store`, and `nix build`; record the dependency review for the `Cargo.toml` additions beyond NV's set (none expected) in the PR description (constitution constraint); confirm the release binary and Nix build exclude the `test-store` feature (see T014).
- [X] T068 [P] Live spike S1: first register a private OAuth client for cf-vault in a Cloudflare account (`POST /accounts/{id}/oauth_clients`, public client, `authorization_code` and `refresh_token` grants, redirect `http://127.0.0.1:8250/callback`, scopes from `GET /oauth/scopes`) and record its ID (not a secret); making it public is permanent and needs domain verification, so decide that only after S1 to S4. Then, with that client, confirm an access token works as `Authorization: Bearer` against `/client/v4` and as `CLOUDFLARE_API_TOKEN` for `wrangler whoami` and a Terraform plan; record the result in `research.md`.
- [X] T069 [P] Live spike S2: determine which scopes cover Workers, DNS, R2 and token management and whether an OAuth session can act as an R2 parent; record in `research.md` and, if it can, amend spec FR-015 and open a follow-up task to extend T053.
- [ ] T070 [P] Live spike S3: record access and refresh token lifetimes and whether refresh tokens rotate; confirm the persist-before-use order from T030 suffices.
- [X] T071 [P] Live spike S4: confirm `http://127.0.0.1:8250/callback` registers on a public client.
- [ ] T072 Release gate: if S1 to S4 pass and a public client is registered, set the built-in client ID from T031, add an integration test for spec User Story 1 scenario 6 (the zero-configuration profile), and add a quickstart live check; if not, amend spec FR-003's first bullet and the README so zero-configuration profiles are not advertised.
- [X] T073 [P] Add a startup-time check in `tests/integration/startup_time.rs` for SC-002: with a valid session and no refresh or broker call, `exec` adds under 1 second before the command starts (measured against a no-op command, with generous CI tolerance and a documented skip flag).
- [X] T074 [P] Add a broker contract test in `tests/integration/broker_contract.rs` (SC-009, FR-014): when `CLOUDFLARE_STS_OPENAPI` points at `stsv1.yaml`, check that the exchange and revoke request fields and the parsed response fields match the schema; skipped when the variable is unset. The broker repository's CI remains the authority for drift.

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: no dependencies.
- **Foundational (Phase 2)**: depends on Setup; blocks every user story.
- **User Stories (Phases 3 to 8)**: all depend on Foundational.
  - US1 is the MVP and is built first; it provides `login`/`exec` wiring and refresh.
  - US2 builds on US1's session and `exec` wiring (T041 and T042 extend T032 and T034).
  - US3 builds on US1's `exec` skeleton (T048 extends T034) but is otherwise independent of US2.
  - US4 depends on US3: direct R2 derivation needs a static-token profile (T054 extends T048).
  - US5 depends on US2 and US3 for the two input paths (T058).
  - US6 depends only on Foundational and T030 (state derivation).
- **Polish (Phase 9)**: after the stories you intend to ship; spikes T068 to T071 can start as soon as an OAuth client is registered and gate only T072.

### Within Each User Story

- Tests first and failing, then implementation.
- Models and helpers before services; services before `exec` wiring; summary output last.
- Tasks touching the same file (`src/app/exec.rs`, `src/app/login.rs`, `src/vault/config.rs`) are sequential and are not marked [P].

### Parallel Opportunities

- Setup: T003, T005, T006.
- Foundational tests T007 to T009 together; implementation T010, T011 together, then T014, T015, T016, T020 together after T013.
- US1 tests T022 to T027 together; T028 and T033 in parallel with test-driven work on different files.
- US2 tests T036 to T038 together.
- US3 tests T044 and T045 together; US4 tests T049 to T051 together.
- US5 tests T055 and T056, T057 in parallel.
- After Foundational, US6 can proceed in parallel with US1 (different files), and US3 can start once T034 exists.
- Spikes T068 to T071 run in parallel.

---

## Parallel Example: User Story 1

```text
# Tests together:
Task: "login_oauth tests in tests/integration/login_oauth.rs"
Task: "exec_session tests in tests/integration/exec_session.rs"
Task: "refresh tests in tests/integration/refresh.rs"
Task: "logout tests in tests/integration/logout.rs"
Task: "override and redaction tests in tests/integration/profile_changes.rs and redaction.rs"

# Then in parallel:
Task: "TokenSet and discovery in src/vault/auth/token.rs"
Task: "logout command in src/app/logout.rs"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Phase 1 Setup, then Phase 2 Foundational.
2. Phase 3 User Story 1 against the mock provider with an explicit `issuer` and `client_id`.
3. **Stop and validate** with quickstart scenario 1 and the redaction tests.
4. The zero-configuration `personal` profile stays release-gated (T031, T072); the MVP does not depend on it.

### Incremental Delivery

1. Setup + Foundational, then US1 (MVP).
2. US3 next if static tokens are the faster path to usable output, then US2 (broker), then US4 (R2), US5 (CI), US6 (list).
3. Each story is tested independently before the next starts.

### Notes

- [P] means different files and no dependency on an incomplete task.
- Commit after each task or logical group; stop at any checkpoint to validate.
- Fake credentials only; never a real token in code, tests, fixtures, or commits (constitution IX, organization data-handling rules).
- File paths follow plan.md's tree; the broker client and the credentials/R2 modules moved after the first implementation (see the module layout note at the end).

## Implementation notes (deviations from the tasks as written)

- **T001**: `scripts/first-publish.sh` was not copied (it publishes nix-vault); the flake's cachix settings were removed (they carried nix-vault's cache key). `scripts/check-release-build.sh` is new.
- **T002**: `sha2` is a dev-dependency only (the PKCE mock checks the challenge). The runtime does not need it: see T052.
- **T005**: the mock provider, broker and Cloudflare API are new (`tests/helpers/{mock,provider,broker,cloudflare}.rs`) rather than copies of nix-vault's helper, because cf-vault needs redirects and response headers.
- **T014**: the `test-store` feature also gates the other test hooks: `CF_VAULT_STORE_UNAVAILABLE`, `CF_VAULT_FORCE_INTERACTIVE`, `CF_VAULT_API_URL`, `CF_VAULT_CALLBACK_TIMEOUT_MS`, `CF_VAULT_RETRY_DELAY_MS`. `scripts/check-release-build.sh` fails when any is present in a binary; it passes for `cargo build --release` and for the Nix build, and fails for a `test-store` build.
- **T015 (V1)**: verified. `apple-native-keyring-store` uses the Security framework through `security-framework` and starts no subprocess, so no secret reaches a command line. The real-keychain smoke test (`cargo test -- --ignored keyring_smoke`) passes on macOS.
- **T022, T059**: `login` for an OAuth profile is allowed without a terminal when `--no-browser` is given (for example over SSH); without that flag it refuses. Token profiles always need a terminal for the hidden prompt.
- **T052**: the temporary-credentials API takes the parent token as the bearer and the parent's access key id (the token's id) in the body, so the SHA-256 "parent secret" is not needed and is not computed. The token id comes from the account's token-verify endpoint, falling back to the user's.
- **Issuer scheme**: `endpoint_allowed` accepts `https`, or `http` on a loopback address (needed for local test servers; also harmless for loopback sign-in), so `oauth2.issuer` is "https or loopback http" rather than "https only".
- **Config location**: `~/.config/cf-vault/config.toml` on macOS and Linux, as nix-vault, not `~/Library/Application Support`.
- **T068 to T072** (live spikes S1 to S4 and the release gate) need a real Cloudflare account and a registered OAuth client and have not been run. Until they are, the zero-configuration `type = "oauth2"` profile fails with an explanatory message (`CLOUDFLARE_CLIENT_ID` is empty in `src/vault/auth/mod.rs`).
- **Live check without an account (partial S4/R1)**: Cloudflare's public discovery document was read and cf-vault's discovery and authorization URL work against it (see `research.md` R1). Registering a client and everything after it still needs an account.
- **Live sign-in against Cloudflare Access for SaaS** (not S1 to S4, which are about `dash.cloudflare.com`): login, keychain storage, `exec` and a rotating refresh all worked; see `research.md` R1.
- **Live exchange against a deployed cloudflare-sts broker**: token and R2 credentials issued, usable (`tokens/verify` active), released on exit; see `research.md` R1.
- **Live `tofu plan` under `cf-vault exec`** (R2 state backend through a `credential_process` helper, Cloudflare provider with the brokered token): worked; the remaining errors were other providers' credentials, outside cf-vault.
- **S2 partly answered** from the live OAuth scope catalog (scope ids for DNS, Zone, Workers, R2, Secrets Store, Access and API-token creation exist); the tests that need a registered client (S1, S3, S4 and the token-minting part of S2) are still open. See `research.md` R1.
- **Spikes S1, S2 and S4 are done** (T068, T069, T071), against a private client; **S3 (T070)** has the lifetime (about an hour) but not yet the rotation, and **T072 (release gate)** needs the decision to make the client public (permanent; needs domain verification) and that `openid` is refused, so the built-in client gets no ID token. Details in `research.md` R1.
- **ID token checks** (FR-006a), taken from the cloudflare-sts client: issuer, audience, expiry and a sign-in nonce, also after a refresh (no nonce). Verified live against a Cloudflare Access for SaaS app: Access echoes the nonce and the checks pass. Not backported from that client: the R2 prefix variables and `whoami` (decided against).
- **Module layout** (changed after the first implementation): no directory holds only a `mod.rs`. The broker client is `src/vault/auth/sts.rs` (it is OAuth 2.0 Token Exchange, so it lives with `auth`); `src/vault/cloudflare/` holds `credentials.rs` (the `CredentialSet`) and `r2.rs`.
