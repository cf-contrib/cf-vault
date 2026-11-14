# Configuration

Profiles live in `~/.config/cf-vault/config.toml` (or `$XDG_CONFIG_HOME/cf-vault/config.toml`, or
the path in `--config` / `CF_VAULT_CONFIG`). Every top-level table is a profile named after the
table: 1–64 characters of `A-Za-z0-9_.-`, starting with a letter or digit.

**The file never holds secrets.** A key such as `token`, `secret`, `password`, `access_token`,
`client_secret` or `refresh_*` is rejected, unknown keys are errors, and every profile is checked
before any command runs, with all problems reported together. Errors name the profile and key and
never a value.

## Keys

| Table | Key | Notes |
|-------|-----|-------|
| `[p]` | `type` | Required: `oauth2` or `api_token`. |
| `[p]` | `account_id` | Required: the Cloudflare account id. |
| `[p.oauth2]` | `issuer`, `client_id` | Your own identity provider; they go together. `https`, or `http` on a loopback address. |
| `[p.oauth2]` | `scopes` | Requested scopes. Default: `openid`, plus `offline_access` when the provider lists it. |
| `[p.oauth2]` | `redirect_port` | Loopback port of the sign-in callback, default `8250`. Cloudflare matches redirect URIs exactly, so register this one. |
| `[p.oauth2.exchange]` | `issuer` | Trade the ID token at this broker (RFC 8693). Its metadata supplies the endpoints and the identity provider; see [endpoint discovery](#endpoint-discovery). |
| `[p.oauth2.exchange]` | `token_endpoint`, `revocation_endpoint` | The broker's endpoints, for a broker without metadata or to override what it publishes. Without `issuer`, `token_endpoint` is required. `revocation_endpoint` is optional: without one the token is not released and expires on its own. |
| `[p.oauth2.exchange]` | `scopes` | What to ask the broker for, sent as the space-separated `scope`. For cloudflare-sts each scope is a broker profile such as `infra-admins:tofu-plan`. Default: none. |
| `[p.oauth2.exchange]` | `audience` | The `audience` to ask for, when the broker wants one. |
| `[p.oauth2.exchange]` | `provider` | The broker's name for the identity provider; only needed when its metadata lists several. Needs `issuer`. |
| `[p.r2]` | `bucket` | Exactly one bucket (use one profile per bucket). Not together with `exchange`. See [R2](r2.md) for where the credentials come from. |
| `[p.r2]` | `permission` | `object-read-write` (default) or `object-read-only`. |
| `[p.r2]` | `prefixes` | Key prefixes the credentials are limited to; default the whole bucket. |

`r2` is valid on `api_token` profiles and on `oauth2` profiles without `exchange`; with `exchange`
the broker profile decides what is issued, so `r2` is rejected. The table in [R2](r2.md) says when
it works.

## How an OAuth profile resolves

| `issuer` + `client_id` | `exchange` | Behaviour |
|---|---|---|
| absent | absent | Cloudflare's own sign-in with cf-vault's registered client (**not available yet**: the profile fails and names the alternatives) |
| absent | present, with `issuer` | provider and client discovered from the broker's metadata; the ID token is exchanged |
| absent | present, without `issuer` | rejected: with no metadata to read, the provider must be named in `oauth2` |
| present | absent | your provider; its access token is delivered as is (nothing assumes Cloudflare accepts it) |
| present | present | your provider; its ID token is exchanged at the broker |

## Endpoint discovery

An `exchange` may name its broker by `issuer` instead of spelling out its endpoints. cf-vault then
reads the broker's metadata, from `<origin>/.well-known/oauth-authorization-server<path>` (RFC
8414) or, failing that, `<issuer>/.well-known/openid-configuration` (OpenID Connect), and takes the
`token_endpoint`, the `revocation_endpoint` and the identity providers people sign in with from it:

```toml
[production.oauth2.exchange]
issuer = "https://cloudflare-sts-api.example.com"
scopes = ["infra-admins:tofu-plan"]
```

* An endpoint written in the profile always wins over the discovered one, so a broker with wrong
  or missing metadata can be fixed key by key.
* A broker with no metadata at all is named by its endpoints. The sign-in provider cannot then be
  discovered, so `oauth2.issuer` and `oauth2.client_id` are required:

  ```toml
  [production.oauth2]
  issuer = "https://id.example.com"
  client_id = "cf-vault"

  [production.oauth2.exchange]
  token_endpoint = "https://broker.example.com/token"
  revocation_endpoint = "https://broker.example.com/revoke"   # optional
  scopes = ["cloudflare:dns"]
  ```
* The metadata is read when a command talks to the broker (`login`, `exec`), once per process, and
  not at all when `exec` has both endpoints set. `list` never touches the network for it.
* The document's `issuer` must equal the configured one, it may be at most 256 KB, and every
  endpoint taken from it must be `https` (or loopback `http`) on the broker's own host.

## Examples

```toml
# Team access through a broker; the provider comes from the broker's metadata
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2]
scopes = ["openid", "email", "offline_access"]   # see docs/broker.md

[production.oauth2.exchange]
issuer = "https://cloudflare-sts-api.example.com"
scopes = ["infra-admins:tofu-plan"]

# Cloudflare's own OAuth, with a client you registered
[personal]
type = "oauth2"
account_id = "abc123"

[personal.oauth2]
issuer = "https://dash.cloudflare.com"
client_id = "<your client id>"
scopes = ["offline_access", "dns.write", "zone.write"]

# A static API token, with temporary R2 credentials for one bucket
[ci-state]
type = "api_token"
account_id = "abc123"

[ci-state.r2]
bucket = "org-terraform-state"
permission = "object-read-write"
prefixes = ["github.com/example-org/app/"]
```
