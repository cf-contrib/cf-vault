# Contract: Configuration File (TOML)

**Spec**: [../spec.md](../spec.md) | **Model**: [../data-model.md](../data-model.md)

Location: `$CF_VAULT_CONFIG` or `--config`, else `$XDG_CONFIG_HOME/cf-vault/config.toml`, else
`~/.config/cf-vault/config.toml` (the same on macOS and Linux, as nix-vault). No global section:
every top-level table is a profile and its name is the table name. Secrets are never valid anywhere
in this file.

## Examples

Minimal, Cloudflare's own sign-in (release-gated, see research R1):

```toml
[personal]
type = "oauth2"
account_id = "abc123"
```

Federated sign-in discovered from the broker:

```toml
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2.exchange]
url = "https://cloudflare-sts-api.example.com"
profile = "infra-admins:tofu-plan"
```

Explicit provider, with exchange:

```toml
[production.oauth2]
issuer = "https://identity.example.com"
client_id = "client-id"
```

Static token with direct R2 credentials:

```toml
[ci-state]
type = "token"
account_id = "abc123"

[ci-state.r2]
bucket = "org-terraform-state"
permission = "object-read-write"
prefixes = ["github.com/example-org/app/"]
```

## Keys

| Table / key | Required | Notes |
|-------------|----------|-------|
| `type` | yes | `oauth2` or `token`. |
| `account_id` | yes | Cloudflare account ID. |
| `[<p>.oauth2]` `issuer`, `client_id`, `scopes`, `redirect_port` | no | `issuer` and `client_id` go together. `redirect_port` defaults to 8250 (Cloudflare matches redirect URIs exactly, so the port is fixed). |
| `[<p>.oauth2.exchange]` `url`, `profile`, `provider` | no | `url` and `profile` required when the table exists; `provider` only to disambiguate. |
| `[<p>.r2]` `bucket`, `permission`, `prefixes` | no | Not allowed together with `exchange`. `bucket` (a single string) required when present; a second bucket needs a second profile. |

## Errors (examples, never include values)

```
cf-vault: config: profile "production": unknown key "oauth2.exhange" (did you mean "exchange"?)
cf-vault: config: profile "production": "client_id" requires "issuer"
cf-vault: config: profile "ci-state": secret-like key "token" is not allowed; use `cf-vault login -p ci-state`
```

Strict decoding: unknown keys are errors. Validation runs per profile and reports every offending
profile, not just the first.
