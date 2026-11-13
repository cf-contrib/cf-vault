# Contract: Broker Client (cloudflare-sts API, consumed not defined)

**Spec**: [../spec.md](../spec.md) | **Source of truth**: `cf-contrib/cloudflare-sts`,
`crates/cloudflare-sts-sdk/openapi/sts/v1/stsv1.tsp` (compiled `stsv1.yaml`). cf-vault introduces no
protocol of its own (FR-011, FR-014). If the broker contract changes, update this document and
the contract tests together.

All requests: `Content-Type: application/x-www-form-urlencoded`, body at most 16 KiB, no client
authentication (the subject token is the proof). All bodies, headers, and errors are treated as
secret-bearing: never logged.

## Discovery: `GET {url}/.well-known/oauth-authorization-server`

Used only when `exchange` is present without an explicit `oauth2.issuer`. Reads:

```json
{
  "issuer": "https://cloudflare-sts-api.example.com",
  "token_endpoint": "https://…/oauth/token",
  "revocation_endpoint": "https://…/oauth/revoke",
  "identity_providers": [{"name": "com.cloudflare.access", "issuer": "https://…", "client_id": "…"}]
}
```

Rules: `issuer` MUST equal the configured URL (no trailing slash difference); endpoints MUST be
`https` on the same host (loopback `http` allowed in tests); zero providers is an error; several
providers require `exchange.provider`, otherwise the error lists the names.

## Exchange: `POST {token_endpoint}`

| Field | Value |
|-------|-------|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | The user's ID token |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:id_token` |
| `audience` | omitted (default `https://api.cloudflare.com`) |
| `profile` | `exchange.profile` |
| `ttl` | only when `--ttl` is given |

`requested_token_type` is omitted: the broker issues what the profile has.

Success (`200`, `Cache-Control: no-store`), fields cf-vault uses; unknown fields are ignored:

| Field | Use |
|-------|-----|
| `access_token?` | `CLOUDFLARE_API_TOKEN`. Absent for bucket-only profiles (`token_type: "N_A"`). |
| `token_id?` | Shown (truncated) in the summary. |
| `account_id?` | Compared with the profile's `account_id`; a difference is a failure before the command starts (error names the profile and both IDs). `CLOUDFLARE_ACCOUNT_ID` is the profile's value. |
| `expires_in`, `expires_at` | Summary line, earliest expiry. |
| `bucket?` | `name`, `access_key_id`, `secret_access_key`, `session_token`, `prefixes`, `endpoint`, `expires_on` → the R2 variables. |
| `profile` | Summary line. |

Errors (`400`, `500`, `503`): `{ "error": <code>, "error_description": <text> }` with codes
`invalid_request`, `invalid_target`, `unsupported_grant_type`, `server_error`,
`temporarily_unavailable`. cf-vault shows the code and description (the description for caller
mistakes is meant for humans), never the request body. `503` is retried once after one second;
other errors are not retried. No fallback to a weaker credential is ever attempted (spec
edge case).

## Revoke: `POST {revocation_endpoint}`

Form fields `token` (the `access_token`) and `token_type_hint=access_token`. Always `200`. Called
after the child exits when an `access_token` was issued; any failure is a warning and does not
change the exit code (FR-013). R2 credentials cannot be revoked; the summary says so.

## Contract tests

A mock broker (an in-process loopback HTTP server in `tests/helpers/broker.rs`) implements these three endpoints and the error
shapes above. A recorded-schema test compares cf-vault's request fields to `stsv1.yaml` when that
file is available at `CLOUDFLARE_STS_OPENAPI` (optional, skipped otherwise); CI of the broker repo
is the authority for drift.
