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
| `[p]` | `type` | Required: `oauth2` or `token`. |
| `[p]` | `account_id` | Required: the Cloudflare account id. |
| `[p.oauth2]` | `issuer`, `client_id` | Your own identity provider; they go together. `https`, or `http` on a loopback address. |
| `[p.oauth2]` | `scopes` | Requested scopes. Default: `openid`, plus `offline_access` when the provider lists it. |
| `[p.oauth2]` | `redirect_port` | Loopback port of the sign-in callback, default `8250`. Cloudflare matches redirect URIs exactly, so register this one. |
| `[p.oauth2.exchange]` | `url`, `profile` | Trade the ID token at this broker for this broker profile. Both required. |
| `[p.oauth2.exchange]` | `provider` | The broker's name for the identity provider; only needed when it lists several. |
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
| absent | present | provider and client discovered from the broker's metadata; the ID token is exchanged |
| present | absent | your provider; its access token is delivered as is (nothing assumes Cloudflare accepts it) |
| present | present | your provider; its ID token is exchanged at the broker |

## Examples

```toml
# Team access through a broker; the provider comes from the broker's metadata
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2]
scopes = ["openid", "email", "offline_access"]   # see docs/broker.md

[production.oauth2.exchange]
url = "https://cloudflare-sts-api.example.com"
profile = "infra-admins:tofu-plan"

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
