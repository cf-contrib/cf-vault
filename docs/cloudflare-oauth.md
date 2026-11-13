# Cloudflare OAuth

Cloudflare supports third-party OAuth clients: people sign in at `dash.cloudflare.com`, and the
application receives a token for the Cloudflare API. cf-vault can use a client you register.

> **Status:** cf-vault does not ship a registered client yet, so the zero-configuration profile
> (`type = "oauth2"` with only `account_id`) fails with a message naming the alternatives. Until a
> client is published, register your own, as below. Making a client public is permanent and needs
> domain verification, so it is a decision for the project, not a step here.

## Register a client

In the dashboard: **Manage account → OAuth clients → Create client** (you need the Super
Administrator or Administrator role, or OAuth Client Write).

| Setting | Value |
|---|---|
| Type | public client, no secret (PKCE) |
| Grant types | `authorization_code` and `refresh_token` |
| Redirect URI | `http://127.0.0.1:8250/callback` (exactly) |
| Scopes | the permissions you need, for example `dns.write`, `zone.write`, `workers-r2.write` |
| Visibility | private (the default): only members of the account can authorize it |

Then:

```toml
[personal]
type = "oauth2"
account_id = "abc123"

[personal.oauth2]
issuer = "https://dash.cloudflare.com"
client_id = "<client id>"
scopes = ["offline_access", "dns.write", "zone.write", "workers-r2.write"]
```

```bash
cf-vault login -p personal
cf-vault exec -p personal -- wrangler deploy
```

## What to know

- **Scope ids** are dot-delimited versions of the API token permission names, for example
  `dns.write`, `zone.write`, `workers-scripts.write`, `workers-r2.write`, `secrets-store.write`,
  `access.write`, `account-api-tokens.write`. `GET /client/v4/oauth/scopes` lists them all.
- **`openid` is refused** for a client like this one ("not allowed to request scope 'openid'"), so
  there is no ID token. That is fine: the access token is what the API needs.
- **`offline_access`** (shown on the consent screen as "Background Access") gives a refresh token.
  Ask for it explicitly.
- **Sensitive scopes**, such as `account-api-tokens.write`, appear under "Sensitive scopes" on the
  consent screen and must be switched on, or the authorization fails.
- **The access token works as `CLOUDFLARE_API_TOKEN`**: it is opaque, lasts about an hour, and the
  API accepts it as a bearer. Refreshing returns a new refresh token each time; cf-vault saves it
  before using the new access token. The `tokens/verify` endpoints do not recognize it, so for
  [R2 credentials](r2.md) cf-vault mints a short-lived token with `account-api-tokens.write`
  instead.
- You can revoke an application's access under *My Profile → Access Management → Connected
  Applications*.
