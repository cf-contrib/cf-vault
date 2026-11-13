# cf-vault

Manage Cloudflare credentials from the command line: sign in once, keep the session in your
system keychain, and run any command with short-lived credentials in its environment only.
Inspired by [aws-vault](https://github.com/99designs/aws-vault) and
[nix-vault](https://github.com/nixos-contrib/nix-vault).

```sh
cf-vault login -p production
cf-vault exec -p production -- terraform plan
```

- **OAuth 2.0 sign-in** (Authorization Code with PKCE) in your browser, automatic refresh, session in
  the macOS Keychain or the Linux Secret Service.
- **Static API tokens** as an alternative, stored the same way.
- **Token exchange** (RFC 8693) at an optional broker such as
  [`cf-contrib/cloudflare-sts`](https://github.com/cf-contrib/cloudflare-sts): short-lived,
  policy-scoped API tokens and R2 credentials, released again when the command exits.
- **Temporary R2 credentials** for one bucket, derived from a stored API token when there is no
  broker.
- **CI/CD** without a browser or keychain, using credentials from the environment.

macOS and Linux. There is no server, daemon or database; the secret never leaves your machine
except to talk to Cloudflare, your identity provider and your broker.

## Install

```sh
nix profile install github:cf-contrib/cf-vault
# or, from a checkout
cargo install --path .
```

## Commands

| Command | |
|---|---|
| `cf-vault login -p NAME [--no-browser]` | Signs in (OAuth profile) or asks for a hidden API token (token profile) and stores the session. The old session is replaced only after the new sign-in succeeds. |
| `cf-vault logout -p NAME` | Deletes the stored session; the refresh token is revoked at the provider on a best-effort basis. |
| `cf-vault list [--json]` | Profiles, type, account and session state (`signed in`, `expired`, `not signed in`, `static token`). Never shows a secret. |
| `cf-vault exec -p NAME [--ttl 10m] -- COMMAND…` | Runs the command with credentials in its environment. Expiring sessions are renewed first; the command is not started when credentials cannot be obtained. |

The profile is given with `-p`/`--profile`, exactly once, or with `CF_VAULT_PROFILE` (the flag
wins). Other settings: `--config` / `CF_VAULT_CONFIG` (default `~/.config/cf-vault/config.toml`),
`--state-dir` / `CF_VAULT_STATE_DIR` (lock files only), `-q`, `-v`.

What each command reads, writes and runs:

| Command | Reads | Writes | Runs / contacts |
|---|---|---|---|
| `login` | config, the profile's session | the profile's session | your browser; a loopback listener while signing in; the identity provider |
| `logout` | config, the profile's session | deletes the session | the provider's revocation endpoint |
| `list` | config, sessions (expiry only) | nothing | nothing |
| `exec` | config, the profile's session, `CF_VAULT_ID_TOKEN`, `CLOUDFLARE_API_TOKEN` | the session, only after a refresh; empty lock files | your command; the provider (refresh), the broker, the Cloudflare API (R2) |

### What the command receives

| Variable | When |
|---|---|
| `CLOUDFLARE_API_TOKEN` | always, except for a broker profile that issues only R2 credentials |
| `CLOUDFLARE_ACCOUNT_ID` | always (the profile's account) |
| `CLOUDFLARE_R2_ACCESS_KEY_ID`, `…_SECRET_ACCESS_KEY`, `…_SESSION_TOKEN`, `…_ENDPOINT`, `…_BUCKET` | only when R2 credentials are issued |

Inherited `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_R2_*` that the profile does not grant are removed
from the command's environment. **`AWS_*` variables are never set, changed or removed.** For
Terraform's S3 backend, point an AWS `credential_process` at a helper that reads `CLOUDFLARE_R2_*`,
such as [`tf-contrib/terraform-cloudflare-backend`](https://github.com/tf-contrib/terraform-cloudflare-backend).

In an interactive session an inherited `CLOUDFLARE_API_TOKEN` is replaced by the profile's, with a
one-line notice on stderr that never shows the value.

## Configuration

Every top-level table is a profile named after the table. **No secrets belong in this file**; a
key such as `token`, `secret`, `password` or `refresh_*` is rejected. See
[`config.example.toml`](config.example.toml).

```toml
# Static API token, with temporary R2 credentials for one bucket
[ci-state]
type = "token"
account_id = "abc123"

[ci-state.r2]
bucket = "org-terraform-state"       # exactly one; use one profile per bucket
permission = "object-read-write"     # or "object-read-only"
prefixes = ["github.com/example-org/app/"]

# Federated sign-in: the identity provider is discovered from the broker
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2.exchange]
url = "https://cloudflare-sts-api.example.com"
profile = "infra-admins:tofu-plan"
# provider = "com.cloudflare.access"  # only when the broker lists several

# Your own provider (a public client with PKCE; redirect http://127.0.0.1:8250/callback)
[staging]
type = "oauth2"
account_id = "xyz789"

[staging.oauth2]
issuer = "https://identity.example.com"
client_id = "client-id"
# redirect_port = 8250
```

How an OAuth profile resolves:

| `oauth2.issuer` + `client_id` | `oauth2.exchange` | Behaviour |
|---|---|---|
| absent | absent | Cloudflare's own sign-in with cf-vault's registered client (**not available yet**, see below) |
| absent | present | provider and client discovered from the broker; the ID token is exchanged |
| present | absent | your provider; its access token is delivered as is (nothing assumes Cloudflare accepts it) |
| present | present | your provider; its ID token is exchanged at the broker |

`r2` is valid on `type = "token"` profiles only (an OAuth session has no parent access key), and
never together with `exchange` (the broker profile decides what is issued).

## CI/CD

Without a terminal (standard input is not a terminal) nothing is prompted, stored or read from the
keychain:

- any profile **without** `exchange` takes its token from `CLOUDFLARE_API_TOKEN`, delivered as is;
- a profile **with** `exchange` takes an identity token from `CF_VAULT_ID_TOKEN` and exchanges it;
  `CLOUDFLARE_API_TOKEN` is not a substitute;
- with nothing supplied, `exec` fails at once and never waits for input.

```sh
CF_VAULT_ID_TOKEN="$ACTIONS_ID_TOKEN" cf-vault exec -p production -- terraform apply
```

## Known limitations

- **Forced termination.** `SIGKILL` cannot be caught, so a broker token is not released if cf-vault
  is killed that way; it expires on its own. Keep lifetimes short.
- **Long-running commands.** Credentials are obtained before the command starts and are not renewed
  while it runs. A broker token or R2 credentials can expire under a long command; `--ttl` asks for
  a longer lifetime (the broker caps it at the profile's maximum). Directly derived R2 credentials
  last 15 minutes unless `--ttl` is given.
- **R2 credentials cannot be revoked early.** They expire. A `credential_process` helper does not
  pass the expiry on, so a run longer than the credentials' lifetime can fail to save Terraform
  state.
- **Cloudflare's own sign-in is not available yet.** The zero-configuration `type = "oauth2"` profile
  needs a Cloudflare OAuth client registered for cf-vault; until then it fails with a message that
  names the alternatives (your own `issuer` and `client_id`, a token profile, or a broker). Whether a
  Cloudflare OAuth access token can be used as an API bearer token, and which scopes it needs, is
  still to be confirmed against a live account.
- **Direct R2 needs a static token.** An OAuth session cannot derive temporary R2 credentials without
  a broker.
- **No plaintext fallback.** Without a usable keychain (for example a headless Linux host without a
  Secret Service), `login` and any command that needs a stored session fail with a clear error.
  Supply credentials through the environment instead.

## Development

```sh
cargo test --features test-store     # unit and integration tests
cargo clippy --all-targets --features test-store -- -D warnings
nix build
scripts/check-release-build.sh       # a release build must contain no test-only hooks
```

The integration tests drive the real binary against loopback mock servers (an OIDC provider, a
broker and the Cloudflare API) with fake credentials only. They need the **`test-store`** cargo
feature, which adds test hooks (a file-backed credential store, a forced-interactive switch, an API
URL override and shortened timeouts, all selected by `CF_VAULT_*` variables). It is never enabled by
default or in releases, and `scripts/check-release-build.sh` fails if any hook is found in a
release binary.

`CLOUDFLARE_STS_OPENAPI=/path/to/stsv1.yaml cargo test --features test-store broker_contract`
checks the fields cf-vault uses against the broker's compiled OpenAPI schema.

## License

MIT, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
