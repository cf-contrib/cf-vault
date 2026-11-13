# Contract: Command-Line Interface

**Spec**: [../spec.md](../spec.md) | Constitution II: every command documents what it reads, writes,
and executes. Errors go to stderr with a non-zero exit; stdout is stable and script-safe.

Profile selection (`login`, `logout`, `exec`): `-p`/`--profile <name>`, required, given **exactly
once** (a second `-p` is a usage error, not a merge). Default from `CF_VAULT_PROFILE`; the flag wins
when both are set. With neither, the command fails and lists the configured profiles. `list`
takes no profile.

Global: `-q`/`--quiet` (warnings and errors only), `-v`/`--verbose` (debug detail, still redacted),
`--config <path>` (also `CF_VAULT_CONFIG`; default `<user config dir>/cf-vault/config.toml`),
`--version`, `--help`.

## `cf-vault login -p <profile> [--no-browser]`

| | |
|-|-|
| Reads | Config; the credential-store item for the profile (to detect an existing session). |
| Writes | The credential-store item for the profile. Nothing on disk. |
| Executes | Opens the system browser (unless `--no-browser`). Starts a loopback HTTP listener for the callback for the duration of sign-in. |

- `type = "oauth2"`: Authorization Code + PKCE (S256), `state` verified, loopback redirect
  `http://127.0.0.1:8250/callback` by default, a 5-minute timeout. With `--no-browser` (or when no
  browser can be opened) the authorization URL is printed on stderr.
- `type = "token"`: reads the token from the terminal without echo. Requires a TTY and a working
  credential store.
- Exit: `0` signed in; `1` failure (message names the profile and cause, never a secret).
- Existing session is replaced only after the new sign-in succeeds.

## `cf-vault logout -p <profile>`

Deletes the credential-store item. For `oauth2` profiles the refresh token is revoked at the
provider on a best-effort basis (failure is a warning). Succeeds if nothing was stored. Exit `0`.

## `cf-vault list [--json]`

Reads config and, per profile, whether a session item exists and whether it is expired (reads the
item but prints no secret value). Default output is a table; `--json` is the stable script format:

```json
[{"profile":"production","type":"oauth2","account_id":"xyz789","exchange":true,"state":"signed in"}]
```

`state` is one of `signed in`, `expired`, `not signed in`, `static token`. Missing config: prints
the expected path on stderr, exit `1`.

## `cf-vault exec -p <profile> [--ttl <duration>] -- <command> [args...]`

| | |
|-|-|
| Reads | Config; the profile's session; (non-interactive) `CF_VAULT_ID_TOKEN`, `CLOUDFLARE_API_TOKEN`. |
| Writes | The profile's session item, only when a refresh succeeded. |
| Executes | The given command, once credentials are in hand. Network: provider token endpoint (refresh), broker `/oauth/token` and `/oauth/revoke`, Cloudflare API (R2 derivation). |

Flow: resolve profile → obtain a credential set (see order below) → build environment → run the
command → release the broker token → exit with the command's status.

Credential order:

1. Noninteractive (stdin not a terminal): `CF_VAULT_ID_TOKEN` for exchange profiles; for every
   other profile (static-token or OAuth) `CLOUDFLARE_API_TOKEN`, delivered as is. Neither → fail
   within seconds, never prompt.
   No credential store access, nothing persisted.
2. Interactive: the stored session (refreshed under a lock when expired). An inherited
   `CLOUDFLARE_API_TOKEN` is replaced, with the one-line stderr notice
   `cf-vault: overriding CLOUDFLARE_API_TOKEN from the environment with profile "<name>"`.

Flags:

| Flag | Meaning |
|------|---------|
| `--ttl <d>` | Requested lifetime (`10m`, `1h`): sent to the broker as `ttl`, or used as `ttlSeconds` for direct R2 derivation (default 15m for direct R2; the broker applies its own profile `ttl` when `--ttl` is absent). Minimum `1m`. |

Exit codes: the command's code; `128+n` when killed by signal `n`; `127` command not found;
`1` cf-vault failed before starting the command (credentials, config, network, store).

Signals: `SIGINT` reaches the child via the terminal; `SIGTERM`/`SIGHUP` are forwarded; cf-vault
waits, revokes, then exits.

Stderr summary (no secrets), for example:

```
cf-vault: profile production (expires 2026-11-13T12:15:00Z)
cf-vault: R2 temporary credentials can't be revoked; they expire at 2026-11-13T12:15:00Z
cf-vault: released token 3f2a…
```

## Environment contract (child process)

See the mapping table in [../data-model.md](../data-model.md#environment-mapping-output-of-the-credential-set).
Always removed when not granted: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_R2_*`. Never touched: `AWS_*`.

Inputs read by cf-vault itself: `CF_VAULT_CONFIG`, `CF_VAULT_PROFILE`, `CF_VAULT_ID_TOKEN`, `CLOUDFLARE_API_TOKEN`
(noninteractive static token).
