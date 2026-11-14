# Commands

```text
cf-vault login  -p <name> [--no-browser]                 sign in, or store an API token
cf-vault exec   -p <name> [--ttl 10m] -- <command> ...   run a command with the credentials
cf-vault logout -p <name>                                remove the stored session
cf-vault list   [--json]                                 profiles and session state
```

**`-p`/`--profile`** names the profile, exactly once; `CF_VAULT_PROFILE` is the default. The
other flags are `--config` (`CF_VAULT_CONFIG`), `--state-dir` (`CF_VAULT_STATE_DIR`), `-q` and `-v`.

## login

Runs the browser sign-in (authorization code with PKCE) for `oauth2` profiles and asks for a
hidden API token for `api_token` profiles. The old session is replaced only after the new
sign-in succeeds. For a profile with an `exchange` and an `issuer`, the identity provider and the
client come from the broker's metadata. `--no-browser` prints the sign-in URL instead of opening
it.

## exec

Renews an expiring session first, never starts the command when credentials cannot be obtained,
and releases a broker-issued token when the command ends. If the broker has no revocation
endpoint, nothing is released and the token expires on its own. `--ttl` (for example `10m` or
`1h`, at least one minute) is passed to the broker, which caps it; without it the broker's own
lifetime applies.

The command receives:

| Variable | When |
|----------|------|
| `CLOUDFLARE_API_TOKEN` | always, except for a broker profile that only has a bucket |
| `CLOUDFLARE_ACCOUNT_ID` | always |
| `CLOUDFLARE_R2_ACCESS_KEY_ID`, `…_SECRET_ACCESS_KEY`, `…_SESSION_TOKEN`, `…_ENDPOINT`, `…_BUCKET` | when R2 credentials are issued |

Inherited `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_R2_*` that the profile does not grant are removed;
`AWS_*` is never touched.

## logout

Removes the local session. The refresh token is revoked at the provider where it has a revocation
endpoint.

## list

Profile, type, account, whether it uses an exchange and the session state. `--json` prints the
same for scripts. It never shows a secret.

## Exit statuses

| Status | Meaning |
|--------|---------|
| `0` | success |
| `1` | failure before the command started |
| `2` | usage error |
| `126` / `127` | the command is not executable / not found |
| other | the command's own status (`128+n` when signal `n` ended it) |
