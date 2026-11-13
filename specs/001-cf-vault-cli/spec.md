# Feature Specification: cf-vault CLI

**Feature Branch**: `001-cf-vault-cli`

**Created**: 2026-11-13

**Status**: Draft

**Input**: User description: "Build `cf-vault`, a lightweight, cross-platform CLI for managing Cloudflare credentials, inspired by `aws-vault` and `nix-vault`: OAuth 2.0 (Authorization Code + PKCE) login with keychain storage and refresh, static API tokens, optional RFC 8693 token exchange through a broker such as `cf-contrib/cloudflare-sts`, R2 temporary credentials, process execution with injected credentials, and noninteractive CI/CD use, driven by declarative TOML profiles."

## Clarifications

### Session 2026-11-13

- Q: For a profile with no broker, how should a user turn on temporary R2 credentials? → A: An
  explicit profile setting naming the bucket (for example `r2 = { bucket = "tf-state" }`); R2
  credentials are derived only when it is present and are limited to that bucket.
- Change request (review): there is no `--r2-env aws` option. AWS-style credentials for Terraform's
  S3 backend come from a `credential_process` helper that reads the `CLOUDFLARE_R2_*` variables.
- Change request (review): a profile names exactly one R2 bucket, not a list, because the exported
  R2 variables describe a single credential set (and the broker also issues one bucket per profile).
  A user who needs two buckets uses two profiles.
- Q: In a pipeline with no browser or keychain, which environment variables supply credentials?
  → A: `CLOUDFLARE_API_TOKEN` for a static token, and a `cf-vault`-specific variable
  (`CF_VAULT_ID_TOKEN`) for an identity token to be exchanged at the broker.
- Q: When `exec` runs and `CLOUDFLARE_API_TOKEN` is already set in the user's shell, what happens?
  → A: In an interactive session the profile's credentials replace it and a one-line notice says
  the inherited value was overridden; the inherited token is used only in noninteractive mode.
- Q: In a pipeline, should an OAuth profile with no broker accept `CLOUDFLARE_API_TOKEN` as its
  credential? → A: Yes. Any profile without an `exchange` section accepts it in noninteractive
  mode; the token is delivered as is and nothing is stored. Profiles with `exchange` need
  `CF_VAULT_ID_TOKEN`.
- Q: When `--ttl` is not given, how long do directly derived R2 credentials last? → A: 15 minutes.
  `--ttl` extends them for long runs (for example a slow Terraform apply). With a broker, the
  broker profile's own lifetime applies.
- Q: For a broker profile, what happens if the account ID the broker returns differs from the
  profile's `account_id`? → A: `exec` fails before starting the command, with an error naming the
  profile and both account IDs.
- Change request (review): the profile is selected with `-p`/`--profile <name>` (as in nix-vault
  and `cloudflare-sts`), not as a positional argument, and the flag is given exactly once.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a command with Cloudflare credentials (Priority: P1)

A developer defines a named profile for a Cloudflare account, signs in once through the browser,
and then runs tools such as Terraform or Wrangler under that profile. The tools receive valid
Cloudflare credentials as environment variables for the lifetime of the command only. Nothing is
written to shell profiles, dotfiles, or the project directory.

**Why this priority**: This is the core value of the tool: credentials delivered safely to a
process without the user handling secrets. Every other story builds on it.

**Independent Test**: With a minimal profile and a mocked identity provider, run `login` and then
`exec` with a command that prints its environment. The command sees a Cloudflare API token; the
parent shell does not.

**Acceptance Scenarios**:

1. **Given** an OAuth profile with an explicit provider (`issuer` and `client_id`), **When** the
   user runs `cf-vault login -p personal`, **Then** a browser sign-in completes and the resulting
   session is stored in the operating system's secure credential store.
2. **Given** a signed-in profile, **When** the user runs `cf-vault exec -p personal -- <command>`,
   **Then** the command runs with `CLOUDFLARE_API_TOKEN` set and the exit status of the command
   is returned unchanged.
3. **Given** a signed-in profile whose access has expired but can be renewed, **When** the user
   runs `exec`, **Then** access is renewed automatically without a browser prompt.
4. **Given** a profile whose session can no longer be renewed, **When** the user runs `exec`,
   **Then** the command is not started and the user is told to run `login` again.
5. **Given** a signed-in profile, **When** the user runs `cf-vault logout -p personal`, **Then** all
   stored credentials for that profile are removed and later `exec` calls fail until the next
   `login`.
6. **Given** a profile with only `type = "oauth2"` and an `account_id`, and a Cloudflare OAuth client
   registered for this tool (see the open dependency in Assumptions), **When** the user runs
   `cf-vault login -p personal`, **Then** the same browser sign-in completes through Cloudflare. Until
   such a client exists, this profile fails with a message naming `oauth2.client_id` and the
   static-token alternative.

---

### User Story 2 - Short-lived, policy-scoped credentials through a broker (Priority: P2)

A team member works under a profile that names a credential broker and a broker profile. After
signing in with the organisation's identity provider, `cf-vault` exchanges the identity token for
a short-lived, narrowly scoped Cloudflare API token and, if the broker profile grants it,
temporary R2 credentials. The broker decides who may get what; `cf-vault` only presents the
identity token and delivers the result.

**Why this priority**: This is the secure team workflow and the main differentiator from a plain
token holder, but it depends on the sign-in and execution flow from User Story 1.

**Independent Test**: Against a mock broker that follows the existing `cloudflare-sts` contract,
configure a profile with only an `exchange` section, run `login` and `exec`, and verify the
command receives the credentials the broker returned and that nothing long-lived is stored.

**Acceptance Scenarios**:

1. **Given** a profile with an `exchange` section and no explicit provider, **When** the user logs
   in, **Then** the identity provider and client are discovered from the broker's published
   metadata and the user signs in with it.
2. **Given** a profile with both an explicit provider and an `exchange` section, **When** the user
   logs in, **Then** they sign in with the configured provider and its identity token is
   exchanged at the broker.
3. **Given** a signed-in broker profile, **When** the user runs `exec`, **Then** the command
   receives a short-lived API token and, if issued, R2 access key, secret, and session token.
4. **Given** the broker refuses the exchange (not permitted, profile disabled, token expired),
   **When** the user runs `exec`, **Then** the command is not started and the broker's reason is
   shown without any credential material.
5. **Given** issued credentials, **When** the command finishes, **Then** the issued API token is
   revoked at the broker where the broker supports it, and the user is not blocked if revocation
   fails.

---

### User Story 3 - Static API token profiles (Priority: P2)

A user who cannot or does not want to use browser sign-in stores a Cloudflare API token under a
profile. The token goes into the secure credential store, never into the configuration file, and
is injected into commands like any other credential.

**Why this priority**: It is the simplest fallback and the escape hatch when OAuth is unavailable
for an account or tool.

**Independent Test**: Define a static-token profile, store a fake token, run `exec` with a command
that prints its environment, and confirm the token appears there and nowhere on disk in plain text.

**Acceptance Scenarios**:

1. **Given** a profile of the static-token type, **When** the user runs `login`, **Then** they are
   prompted for the token without echo and it is stored in the secure credential store.
2. **Given** a stored static token, **When** the user runs `exec`, **Then** the command receives
   it as `CLOUDFLARE_API_TOKEN`.
3. **Given** no secure credential store is available, **When** the user tries to store a token,
   **Then** the command fails with a clear error and nothing is written in plain text.

---

### User Story 4 - R2 credentials without a broker (Priority: P3)

A user with a stored static API token and no broker needs S3-compatible access to R2 (for example
Terraform state). `cf-vault` derives temporary R2 credentials from that token at `exec` time and delivers them alongside the API token. `cf-vault` never sets AWS credential
variables; tools that need AWS-style credentials (such as Terraform's S3 backend) read the
Cloudflare R2 variables through a `credential_process` helper outside this tool.

**Why this priority**: It completes the R2 story for users without a broker, but it is only useful
once a basic profile works.

**Independent Test**: With a mocked Cloudflare API, run `exec` on a profile with R2 enabled and
verify the Cloudflare R2 variables are set and that any `AWS_*` variables in the environment reach
the command unchanged.

**Acceptance Scenarios**:

1. **Given** a static-token profile with a stored token and an R2 bucket, **When** the user runs
   `exec`, **Then** the command receives `CLOUDFLARE_R2_ACCESS_KEY_ID`,
   `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, and `CLOUDFLARE_R2_SESSION_TOKEN`, limited to that
   bucket, and the credentials expire shortly after the command is expected to finish.
2. **Given** a profile with no R2 bucket and no broker, **When** the user runs `exec`,
   **Then** no R2 variables are set and no R2 credentials are requested.
3. **Given** the user's environment already contains AWS credentials, **When** the user runs `exec`,
   **Then** the AWS variables reach the command unchanged, whether or not R2 credentials are issued.
4. **Given** an OAuth profile with an R2 bucket and no broker, **When** the configuration is loaded,
   **Then** it is rejected with an explanation that direct R2 credentials need a static-token
   profile (an OAuth session has no parent access key; revisit if live testing shows otherwise).

---

### User Story 5 - Noninteractive CI/CD use (Priority: P3)

A pipeline runs `cf-vault exec` without a browser, keychain, or prompt. Credentials come from the
CI environment (an externally supplied token, or an identity token supplied by the CI system for
broker exchange), and the same `exec` interface and variables apply.

**Why this priority**: It lets teams use one command shape locally and in pipelines, but it
reuses the exchange and execution flows already built.

**Independent Test**: In a clean container with no keychain and no TTY, supply a fake token and a
fake identity token through the environment and verify `exec` succeeds without any prompt and
fails fast, with a clear error, when nothing is supplied.

**Acceptance Scenarios**:

1. **Given** no TTY and no secure credential store, **When** a token is supplied in
   `CLOUDFLARE_API_TOKEN` for any profile without an `exchange` section (static-token or OAuth),
   **Then** `exec` runs the command with it and stores nothing.
2. **Given** an identity token supplied in `CF_VAULT_ID_TOKEN` and a broker profile, **When**
   `exec` runs, **Then** the token is exchanged at the broker and the result delivered.
3. **Given** a noninteractive session with no credentials supplied, **When** `exec` runs, **Then**
   it fails immediately with a non-zero status and never waits for input.

---

### User Story 6 - Inspect profiles (Priority: P3)

A user lists the configured profiles and sees, for each, its authentication method and whether a
usable session exists, without any secret being displayed.

**Why this priority**: A small convenience that makes the rest of the tool discoverable.

**Independent Test**: With several profiles in various states, run `list` and check the output
shows each profile and its state and contains no credential material.

**Acceptance Scenarios**:

1. **Given** several profiles, **When** the user runs `cf-vault list`, **Then** each profile is
   shown with its type and session state (signed in, expired, or not signed in).
2. **Given** no configuration file, **When** the user runs `list`, **Then** a clear message
   explains where the configuration is expected.

---

### Edge Cases

- The browser cannot be opened (headless host): the user is shown the sign-in address to open
  elsewhere, or a clear error if the sign-in cannot complete.
- The sign-in is abandoned or the local callback port is busy: the command times out or fails with
  a clear message and leaves no partial session.
- The broker is unreachable or returns an error: `exec` fails without starting the command and
  without falling back to a weaker credential.
- Two `exec` runs for the same profile start at once while a renewal is due: neither run receives
  an invalid credential, and the stored session is not corrupted.
- A profile has an `account_id` that the signed-in identity cannot access: the failure names the
  profile and the cause, not the credential.
- The broker returns an account ID that differs from the profile's `account_id`: `exec` fails before
  starting the command and names the profile and both account IDs (never a credential), and the
  issued API token is released at the broker.
- The configuration contains something that looks like a secret (token, client secret): the tool
  refuses it or warns and tells the user to use the secure credential store.
- The configuration file is malformed, names an unknown profile type, or sets contradictory
  options: the error identifies the profile and the offending field.
- A child command is interrupted or terminated: signals are forwarded and temporary material is
  cleaned up.
- A command is killed forcibly: no secret remains on disk; short credential lifetimes bound any
  remaining exposure.
- A profile name is unknown: the error lists available profiles.
- `CLOUDFLARE_API_TOKEN` is already set in an interactive shell: the profile's credentials win and
  the user is told the inherited value was overridden.

## Requirements *(mandatory)*

### Functional Requirements

**Profiles and configuration**

- **FR-001a**: `login`, `logout`, and `exec` MUST select the profile with `-p`/`--profile <name>`,
  which MUST be given exactly once (repeating it is an error). When the flag is absent, the
  `CF_VAULT_PROFILE` environment variable supplies the name; when both are present the flag wins.
  With neither, the command fails and lists the available profiles.
- **FR-001**: The tool MUST read declarative configuration containing named profiles, each with an
  authentication type and a Cloudflare account identifier.
- **FR-002**: The tool MUST support profile types for OAuth 2.0 sign-in and for static API tokens.
- **FR-003**: For OAuth profiles, the provider settings and the token-exchange settings MUST each
  be optional, and the tool MUST resolve behaviour as follows:
  - neither present: use Cloudflare's own sign-in with a client registered for this tool (available
    once that client exists; until then the profile fails with an actionable message);
  - exchange settings only: discover the identity provider and client from the broker's published
    metadata;
  - provider settings only: sign in with the configured provider and use its tokens as is, without
    assuming Cloudflare accepts them;
  - both present: sign in with the configured provider and exchange its identity token at the
    broker.
- **FR-004**: The configuration MUST NOT hold secrets. The tool MUST reject or warn about secret
  values found in configuration and direct the user to the secure credential store.
- **FR-005**: Configuration errors MUST name the profile and field at fault and MUST NOT include
  credential values.

**Authentication**

- **FR-006**: `login -p <profile>` MUST authenticate the user by browser-based OAuth 2.0
  Authorization Code with PKCE and store the resulting session in the operating system's secure
  credential store.
- **FR-007**: The tool MUST renew an expired OAuth session automatically when renewal is possible,
  and MUST otherwise instruct the user to log in again.
- **FR-008**: For static-token profiles, `login` MUST read the token without echoing it and store
  it in the secure credential store.
- **FR-009**: `logout -p <profile>` MUST delete all credentials stored for the profile and MUST
  succeed if there is nothing to delete.
- **FR-010**: If no secure credential store is available, the tool MUST fail with a clear error
  and MUST NOT fall back to plain-text storage. Any insecure alternative MUST be an explicit,
  opt-in action with a visible warning.

**Token exchange and R2**

- **FR-011**: When exchange settings are present, the tool MUST obtain credentials by presenting
  the user's identity token to the broker using OAuth 2.0 Token Exchange (RFC 8693), reusing the
  existing `cloudflare-sts` request and response contract and introducing no new protocol.
- **FR-012**: The tool MUST request the broker profile named in configuration and MUST deliver
  exactly what the broker returns: an API token, R2 credentials, or both. If the broker's response
  names an account that differs from the profile's `account_id`, the tool MUST NOT start the
  command and MUST report the profile and both account IDs.
- **FR-013**: The tool MUST release a broker-issued API token after use (RFC 7009) when the broker
  supports it, and a failed release MUST NOT change the command's exit status.
- **FR-014**: The tool MUST function with any broker implementing the same contract and MUST NOT
  depend on `cloudflare-sts` specifics beyond that contract.
- **FR-015**: Without a broker, the tool MUST derive temporary R2 credentials only for a
  static-token profile that names an R2 bucket (exactly one per profile). The credentials MUST be
  limited to that bucket and derived from the stored token with a lifetime of 15 minutes unless
  `--ttl` is given. A profile with no R2 bucket MUST NOT trigger any R2 credential request, and an
  OAuth profile with an R2 bucket and no broker MUST be rejected at configuration load.
- **FR-016**: The command MUST receive only the credentials in the Credential Set. The stored
  identity token and refresh token of an OAuth or broker profile MUST never be placed in the
  command's environment.

**Execution**

- **FR-017**: `exec -p <profile> -- <command> [args...]` MUST run the command with credentials
  injected into its environment only, inherit standard input, output, and error, forward
  interrupt and termination signals, and return the command's exit status.
- **FR-018**: The tool MUST export `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` (the
  profile's account), and, only when R2 credentials exist, `CLOUDFLARE_R2_ACCESS_KEY_ID`,
  `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, `CLOUDFLARE_R2_SESSION_TOKEN`, `CLOUDFLARE_R2_ENDPOINT`, and
  `CLOUDFLARE_R2_BUCKET`. Inherited values of `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_R2_*` that the
  profile does not grant MUST be removed from the command's environment.
- **FR-019**: The tool MUST NOT set, overwrite, or remove AWS credential variables. R2 credentials
  are delivered only under the `CLOUDFLARE_R2_*` names, which AWS-style consumers such as a
  `credential_process` helper read from the child's environment.
- **FR-020**: The tool MUST NOT modify the parent shell's environment, shell startup files, or the
  configuration of the tools it launches.
- **FR-021**: When credentials cannot be obtained, the command MUST NOT be started and the tool
  MUST exit with a non-zero status and an actionable message on standard error.

**Noninteractive use**

- **FR-022**: The tool MUST run without prompts, a browser, or a secure credential store when
  credentials are supplied through the environment, and MUST fail fast, never waiting for input,
  when none are available. For any profile without an `exchange` section (static-token or OAuth), the
  token is read from `CLOUDFLARE_API_TOKEN` and delivered as is; for a profile with an `exchange`
  section, an identity token is read from `CF_VAULT_ID_TOKEN` and `CLOUDFLARE_API_TOKEN` is not
  accepted as a substitute. When a broker profile receives an
  identity token this way, it MUST be used instead of any stored session. A session is
  noninteractive when standard input is not a terminal.
- **FR-022a**: In an interactive session, an inherited `CLOUDFLARE_API_TOKEN` MUST be replaced by
  the profile's credentials, with a one-line notice on standard error that the inherited value was
  overridden (the notice MUST NOT show the value).
- **FR-023**: In noninteractive mode the tool MUST NOT persist any credential.

**Inspection**

- **FR-024**: `list` MUST show every configured profile, its type, and its session state, and MUST
  NOT display any credential value.

**Security and quality**

- **FR-025**: Secrets MUST NOT appear in command-line arguments, logs, error messages, or
  diagnostic output, and MUST be redacted wherever they could be shown.
- **FR-026**: Credential delivery MUST be scoped to the lifetime of the child command; no
  credential file or process may outlive it.
- **FR-027**: The tool MUST run as a single standalone executable on macOS and Linux, requiring no
  server, background service, or database of its own.
- **FR-028**: Documentation MUST state known limitations, including cleanup after forced
  termination, credential renewal during long-running commands, R2 credentials that cannot be
  revoked early, and that a `credential_process` helper does not pass expiry on (long runs can
  outlive the R2 credentials; `--ttl` extends them).

### Key Entities

- **Profile**: A named configuration entry binding an authentication type, a Cloudflare account,
  and optional provider, exchange, and R2 bucket settings. Contains no secrets.
- **Session**: The stored authentication state for a profile (for example OAuth access and renewal
  tokens, or a static token), held in the secure credential store and tied to one profile.
- **Identity Provider**: The OAuth 2.0 / OIDC issuer a user signs in with: Cloudflare, a
  configured issuer, or one discovered from a broker.
- **Broker**: An optional external service that verifies an identity token against its own policy
  and issues short-lived Cloudflare credentials, following the existing `cloudflare-sts` contract.
- **Broker Profile**: A named policy entry at the broker that determines which permissions and R2
  access a verified caller receives.
- **Credential Set**: The values delivered to a command: an API token and, optionally, an R2 access
  key, secret, and session token, each with an expiry where applicable.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A new user with a configured profile (a minimal profile once Cloudflare's client for
  this tool is registered, otherwise one with an explicit provider) can go from installation to
  running a Cloudflare command under that profile in under 5 minutes, including the browser
  sign-in.
- **SC-002**: Starting a command under a signed-in profile with a valid session adds under 1 second
  of delay in the common case where no renewal or broker call is needed.
- **SC-003**: After `logout`, 100% of stored credentials for the profile are gone, and a subsequent
  `exec` fails without starting the command.
- **SC-004**: In automated checks of every command's output, logs, and error paths, zero secret
  values appear, including on failure.
- **SC-005**: In all tested environments, no credential is found in configuration files, shell
  startup files, or any plain-text file after login, execution, and logout.
- **SC-006**: In a clean pipeline environment with no browser or keychain, 100% of `exec` runs with
  supplied credentials succeed without prompts, and 100% of runs without them fail within 5 seconds.
- **SC-007**: Existing AWS credential variables are unchanged in the child process in 100% of
  runs.
- **SC-008**: The `CLOUDFLARE_R2_*` variable names are stable and documented, so a
  `credential_process` helper can serve Terraform's S3 backend with no AWS variables set by the
  tool.
- **SC-009**: The tool works against a second broker implementation that follows the same contract
  with no changes beyond configuration.

## Assumptions

- Terraform's S3 backend is fed through an AWS `credential_process` helper such as
  `tf-contrib/terraform-cloudflare-backend`, which reads `CLOUDFLARE_R2_ACCESS_KEY_ID`,
  `CLOUDFLARE_R2_SECRET_ACCESS_KEY`, and `CLOUDFLARE_R2_SESSION_TOKEN` from its environment. That
  helper is outside this feature. It does not pass expiry on, so a run longer than the R2
  credential lifetime can fail to save state (use `--ttl` for long runs).
- Target platforms for the first release are macOS and Linux (including headless Linux for CI).
  Windows is out of scope.
- The tool is implemented in Rust (reusing the nix-vault codebase as its starting point) and shipped as one executable with a deliberately small set of
  third-party dependencies (project constraint, not a user-facing requirement).
- Configuration lives in a per-user TOML file in the standard user configuration location; its
  exact path and the credential store entry naming are decided in planning.
- Profile names are the TOML table names; `account_id` is required for every profile.
- A static-token profile's token is stored in the secure credential store; in CI any profile
  without an `exchange` section can instead be given its token through the environment.
- The broker contract is the `cf-contrib/cloudflare-sts` HTTP API: RFC 8693 exchange, RFC 7009
  revocation, and RFC 8414 metadata that lists identity providers with their client identifiers.
  Details are confirmed against that repository during planning.
- OAuth sign-in uses a loopback redirect on the local machine; the fixed port used by existing
  `cloudflare-sts` tooling (8250) is the default, to match identity-provider registrations.
- Directly derived R2 credentials last 15 minutes by default (`--ttl` changes it, minimum 1
  minute); they cannot be revoked before expiry, so lifetimes stay short.
- **Open dependency (to be resolved in planning)**: Cloudflare's direct OAuth sign-in is not
  assumed to be available to third-party tools. Planning MUST establish whether Cloudflare offers a
  registrable public OAuth client, with Authorization Code + PKCE, loopback redirects, refresh
  tokens, and scopes sufficient to obtain an API token and R2 credentials. Wrangler's own client
  MUST NOT be reused. If Cloudflare's direct flow is unavailable, the zero-configuration "personal"
  profile described in FR-003 falls back to static tokens or a broker, and the specification will
  be amended.
- The broker's availability, policies, and identity verification are outside this feature; so are
  deploying and operating a broker.
