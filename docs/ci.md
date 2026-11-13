# CI

Without a terminal (standard input is not a terminal), cf-vault prompts for nothing, opens no
browser, reads nothing from the keychain and stores nothing. Credentials come from the
environment:

| Profile | Variable |
|---|---|
| any profile **without** `exchange` (`token` or `oauth2`) | `CLOUDFLARE_API_TOKEN`, delivered as is |
| a profile **with** `exchange` | `CF_VAULT_ID_TOKEN`, an identity token exchanged at the broker (`CLOUDFLARE_API_TOKEN` is not a substitute) |

With nothing supplied, `exec` fails at once and never waits for input. `login` needs a terminal
(or `--no-browser` for the sign-in).

```bash
CLOUDFLARE_API_TOKEN="$TOKEN" cf-vault exec -p ci-state -- tofu apply
CF_VAULT_ID_TOKEN="$ID_TOKEN" cf-vault exec -p production -- tofu apply
```

## GitHub Actions

A workflow can pass its own OIDC token to the broker. For jobs that only need the credentials in
their environment, the [cloudflare-sts action](https://github.com/cf-contrib/cloudflare-sts) does
that without installing anything. Use cf-vault in CI when you want the same command line as on your
machine (`cf-vault exec -p … --`), with the job's identity token in `CF_VAULT_ID_TOKEN`.

## A machine with no keychain

A headless Linux host without a Secret Service cannot store a session: use the environment as
above.
