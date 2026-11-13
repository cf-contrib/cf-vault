# Data Model: cf-vault CLI

**Date**: 2026-11-13 | **Spec**: [spec.md](spec.md) | **Research**: [research.md](research.md)

No database. The only persistent data are the user's TOML config (no secrets) and one
credential-store item per profile. Field names below are logical; encodings are in
[contracts/](contracts/).

## Profile (config, no secrets)

| Field | Type | Rules |
|-------|------|-------|
| `name` | string | The TOML table name. 1–64 chars of `A-Za-z0-9_.-`, starts alphanumeric. Unique. |
| `type` | enum | `oauth2` or `token`. Required. Unknown value is an error naming the profile. |
| `account_id` | string | Required. Cloudflare account identifier (hex). |
| `oauth2` | OAuth2Settings? | Only for `type = "oauth2"`. Optional. |
| `oauth2.issuer` | URL? | `https` only. Provider is discovered from it. Needs `client_id`. |
| `oauth2.client_id` | string? | Public client, no secret. Needs `issuer` unless Cloudflare default is used. |
| `oauth2.redirect_port` | int? | Loopback port for the sign-in callback, default 8250. |
| `oauth2.scopes` | string[]? | Defaults to `["openid"]` plus `offline_access` when the provider supports it. |
| `oauth2.exchange` | ExchangeSettings? | Optional. Presence turns on broker exchange. |
| `oauth2.exchange.url` | URL | Required. `https` (loopback `http` allowed for tests). |
| `oauth2.exchange.profile` | string | Broker profile name, sent as `profile`. Required in v1. |
| `oauth2.exchange.provider` | string? | Broker's identity-provider name; needed only if several are listed. |
| `r2` | R2Settings? | Optional. Rejected on profiles with `exchange` (the broker profile decides) and on `oauth2` profiles (direct R2 needs a static-token parent; revisit after spike S2). |
| `r2.bucket` | string | Exactly one bucket name (a valid R2 bucket name). Required when `r2` is present; a list is rejected with "use one profile per bucket". |
| `r2.permission` | enum? | `object-read-write` (default), `object-read-only`. |
| `r2.prefixes` | string[]? | Optional key-prefix limits. |

**Validation**

- Unknown keys are errors (strict decoding), reported with profile and key, never the value.
- Any key whose name looks secret (`token`, `secret`, `password`, `client_secret`, `refresh_*`) is
  rejected with "use `cf-vault login`; secrets never go in config" (FR-004).
- Resolution matrix (FR-003):

| `oauth2.issuer`/`client_id` | `oauth2.exchange` | Behaviour |
|----|----|----|
| absent | absent | Cloudflare provider with built-in client (R1 release gate). |
| absent | present | Provider and client discovered from broker; ID token exchanged. |
| present | absent | Configured provider; its access token delivered as is. |
| present | present | Configured provider; its ID token exchanged. |

- `issuer` without `client_id` (or the reverse) is a config error.

## Session (credential store item, one per profile)

Stored as JSON in the OS credential store: service `cf-vault`, account = profile name.

| Field | Type | Notes |
|-------|------|-------|
| `version` | int | Schema version, starts at 1. |
| `kind` | enum | `oauth2` or `token`. Must match the profile `type`, else treated as not signed in. |
| `access_token` | secret | For `oauth2`: provider access token. For `token`: the static API token. |
| `id_token` | secret? | OIDC ID token when the provider issues one (needed for exchange). |
| `refresh_token` | secret? | Present when the provider issued one. |
| `expires_at` | time? | Access token expiry. Absent for static tokens. |
| `id_token_expires_at` | time? | For exchange profiles. |
| `issuer` | string? | Provider issuer the session belongs to (a changed issuer invalidates the session). |
| `client_id` | string? | Same, for the client. |

**State transitions**

```
none --login--> valid --(time passes)--> expired
valid/expired --(exec, refresh ok)--> valid
expired --(exec, no refresh token or refresh rejected)--> expired (tell user to login)
any --logout--> none
```

`list` derives its state label (`signed in`, `expired`, `not signed in`, and `static token` for
`token` profiles) without ever reading secret values into output.

## Credential Set (in memory only, never persisted)

| Field | Type | Notes |
|-------|------|-------|
| `api_token` | secret? | Delivered as `CLOUDFLARE_API_TOKEN`. Absent for bucket-only broker profiles. |
| `api_token_id` | string? | Broker `token_id`, kept only to revoke and log. |
| `account_id` | string | From the profile (or broker response). Delivered as `CLOUDFLARE_ACCOUNT_ID`. |
| `r2` | R2Credentials? | See below. |
| `expires_at` | time? | Earliest expiry among the parts, used in the one-line stderr summary. |
| `revoke` | func? | How to release the API token after exit (broker only). |

**R2Credentials**: `access_key_id`, `secret_access_key`, `session_token` (secrets), `endpoint`,
`bucket`, `prefixes`, `expires_at`. Cannot be revoked; expires.

## Environment Mapping (output of the Credential Set)

| Credential Set field | Variable |
|----------------------|----------|
| `api_token` | `CLOUDFLARE_API_TOKEN` |
| `account_id` | `CLOUDFLARE_ACCOUNT_ID` |
| `r2.access_key_id` | `CLOUDFLARE_R2_ACCESS_KEY_ID` |
| `r2.secret_access_key` | `CLOUDFLARE_R2_SECRET_ACCESS_KEY` |
| `r2.session_token` | `CLOUDFLARE_R2_SESSION_TOKEN` |
| `r2.endpoint` | `CLOUDFLARE_R2_ENDPOINT` |
| `r2.bucket` | `CLOUDFLARE_R2_BUCKET` |

Variables not granted are removed from the child's environment (never inherited). `AWS_*`
variables are never set, changed, or removed; AWS-style consumers (for example a
`credential_process` helper for Terraform's S3 backend) read the `CLOUDFLARE_R2_*` names.

## Broker exchange (in memory)

Request/response shapes: [contracts/broker.md](contracts/broker.md). Identity-provider list entry:
`{name, issuer, client_id}`.
