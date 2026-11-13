# cf-vault

[![CI](https://github.com/cf-contrib/cf-vault/actions/workflows/ci.yml/badge.svg)](https://github.com/cf-contrib/cf-vault/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/cf-contrib/cf-vault)](https://github.com/cf-contrib/cf-vault/releases/latest)
[![Rust](https://img.shields.io/badge/Rust-1.95-DEA584?logo=rust&logoColor=white)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)](#install)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Manage Cloudflare credentials without keeping them in shell profiles, dotfiles or CI variables.
cf-vault signs you in, keeps the session in your system keychain, and runs a command with
short-lived Cloudflare credentials in its environment for that command only. It is inspired by
[aws-vault](https://github.com/99designs/aws-vault) and
[nix-vault](https://github.com/nixos-contrib/nix-vault).

```bash
cf-vault login -p production                      # once: browser sign-in
cf-vault exec -p production -- terraform plan     # credentials exist only for this command
```

```text
 login ──► your keychain (once)
 exec  ──► short-lived credentials ──► your command (terraform, wrangler, ...) ──► released when it ends
```

## Pick your setup

| You want | Use | Read |
|----------|-----|------|
| Team access with policy-scoped, short-lived tokens and R2 credentials | an `oauth2` profile with `exchange` at a [cloudflare-sts](https://github.com/cf-contrib/cloudflare-sts) broker | [Broker](docs/broker.md) |
| Your own identity provider, or Cloudflare's own sign-in with your own client | an `oauth2` profile with `issuer` and `client_id` | [Cloudflare OAuth](docs/cloudflare-oauth.md) |
| A plain API token kept in the keychain, optionally with temporary R2 credentials | an `api_token` profile | [R2](docs/r2.md) |
| CI, or a machine with no keychain | environment variables | [CI](docs/ci.md) |

Every guide is in [docs/](docs/README.md).

## Install

```bash
nix run github:cf-contrib/cf-vault -- --help      # or: nix profile install github:cf-contrib/cf-vault
cargo binstall cf-vault                           # prebuilt binary from the GitHub release
cargo install cf-vault
```

Supported: macOS and Linux. On Linux the session goes to the Secret Service (for example
gnome-keyring or KeePassXC), so one must be running in your session. cf-vault never falls back to
another store: without a usable keychain, `login` fails. A machine without one uses environment
variables: see [CI](docs/ci.md).

## Configuration

Profiles live in `~/.config/cf-vault/config.toml` (or `$XDG_CONFIG_HOME/cf-vault/config.toml`, or
the file named by `--config` / `CF_VAULT_CONFIG`). Each top-level table is a profile with an
`account_id` and a `type`: `oauth2` or `token`.

```toml
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2.exchange]
url = "https://cloudflare-sts-api.example.com"
profile = "infra-admins:tofu-plan"

[ci-state]
type = "api_token"
account_id = "abc123"

[ci-state.r2]
bucket = "org-terraform-state"
```

The file never holds tokens or secrets, and the whole file is validated before any command runs.
Every key is in [Configuration](docs/configuration.md); a full example is
[`config.example.toml`](config.example.toml).

## Commands

```text
cf-vault login  -p <name> [--no-browser]                 sign in, or store an API token
cf-vault exec   -p <name> [--ttl 10m] -- <command> ...   run a command with the credentials
cf-vault logout -p <name>                                remove the stored session
cf-vault list   [--json]                                 profiles and session state
```

* **`-p`/`--profile`** names the profile, exactly once; `CF_VAULT_PROFILE` is the default.
* **login** runs the browser sign-in (authorization code with PKCE) for `oauth2` profiles and asks
  for a hidden API token for `api_token` profiles. The old session is replaced only after the new
  sign-in succeeds.
* **exec** renews an expiring session first, never starts the command when credentials cannot be
  obtained, and releases a broker-issued token when the command ends. The command receives
  `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` and, when R2 credentials are issued,
  `CLOUDFLARE_R2_ACCESS_KEY_ID`, `…_SECRET_ACCESS_KEY`, `…_SESSION_TOKEN`, `…_ENDPOINT` and
  `…_BUCKET`. Inherited `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_R2_*` the profile does not grant are
  removed; `AWS_*` is never touched.
* **logout** removes the local session. The refresh token is revoked at the provider where it has a
  revocation endpoint.
* **list** never shows a secret.

Exit statuses: `0` success; `1` failure before the command started; `2` usage error; `126`/`127`
command not executable / not found; otherwise the command's own status (`128+n` when signal `n`
ended it).

## Limitations

* **Cleanup is best effort** after `SIGKILL`: a broker token is then not released and expires on
  its own.
* **Credentials are not renewed while the command runs**; ask for a longer lifetime with `--ttl`.
* **R2 credentials cannot be revoked early.**
* **Cloudflare's own sign-in needs a client of your own** for now.

The full list is in [docs/limitations.md](docs/limitations.md).

## Development

```bash
nix develop                                                         # pinned Rust toolchain
cargo fmt --check && cargo clippy --all-targets --features test-store -- -D warnings
cargo test --features test-store                                    # unit + integration tests
cargo test -- --ignored keyring_smoke                               # real keychain round trip (manual)
```

The integration tests drive the real binary against loopback mock servers (an OIDC provider, a
broker and the Cloudflare API) with fake credentials only. They need the **`test-store`** cargo
feature, which adds test hooks selected by `CF_VAULT_*` variables. It is never enabled by default
or in releases, and CI fails if a release binary contains any of them.

## License

MIT, see [LICENSE](LICENSE).
