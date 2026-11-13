# Quickstart: Validating cf-vault

**Spec**: [spec.md](spec.md) | **Contracts**: [contracts/](contracts/)

Each scenario proves one user story. Commands use fake values only; never real credentials
(constitution IX). Scenarios 1–6 run entirely against local mocks and are the automated end-to-end
suite; the live checks at the end are manual spikes.

## Prerequisites

- Rust toolchain (version in `rust-toolchain.toml`), macOS or Linux.
- `cargo test` builds and runs everything below against in-process mocks:
  a mock OIDC provider, a mock broker ([contracts/broker.md](contracts/broker.md)), a mock
  Cloudflare API, and an in-memory credential store.
- For the keychain scenario on a real machine: an unlocked macOS login keychain or a running
  Secret Service (e.g. GNOME Keyring) on Linux.

## 1. Sign in and run (User Story 1)

```sh
export CF_VAULT_CONFIG=$(mktemp)        # test config, no secrets
printf '[personal]\ntype="oauth2"\naccount_id="abc123"\n[personal.oauth2]\nissuer="http://127.0.0.1:9000"\nclient_id="test"\n' > "$CF_VAULT_CONFIG"
cf-vault login -p personal --no-browser    # open the printed URL; the mock provider auto-approves
cf-vault exec -p personal -- sh -c 'echo "token set: ${CLOUDFLARE_API_TOKEN:+yes}"'
echo "parent shell: ${CLOUDFLARE_API_TOKEN:-unset}"
cf-vault logout -p personal && cf-vault exec -p personal -- true   # second command must fail, exit 1
```

Expected: `token set: yes`, parent shell `unset`, final command exits `1` without starting.

## 2. Broker exchange (User Story 2)

Config per [contracts/config.md](contracts/config.md) with `[x.oauth2.exchange]` pointing at the
mock broker. `login -p <name>` then `exec -p <name> -- env | grep CLOUDFLARE_`.
Expected: `CLOUDFLARE_API_TOKEN` equals the mock's `access_token`; the mock sees one exchange and,
after the command exits, one revoke; nothing long-lived is in the credential store beyond the
ID/refresh tokens.

Failure case: make the mock return `invalid_request`. Expected: command not started, the broker's
description on stderr, no token text.

## 3. Static token (User Story 3)

```sh
cf-vault login -p ci-state          # type "token": prompts without echo (a TTY is required)
cf-vault exec -p ci-state -- sh -c 'echo ${CLOUDFLARE_API_TOKEN:+yes}'
```

Expected: `yes`. With the store made unavailable (test hook), `login` fails with a clear error and
no file contains the token.

## 4. R2 credentials (User Story 4)

Profile with `[x.r2] bucket="tf-state"` against the mock Cloudflare API.

```sh
AWS_ACCESS_KEY_ID=preset cf-vault exec -p ci-state -- env | grep -E '^(CLOUDFLARE_R2_|AWS_)'
```

Expected: the three `CLOUDFLARE_R2_*` credentials plus the endpoint and bucket are shown, and
`AWS_ACCESS_KEY_ID=preset` is unchanged (no `AWS_*` variable is ever set or removed). A profile
without `r2` triggers no R2 request (assert on the mock).

Optional manual check: with `tf-contrib/terraform-cloudflare-backend` as the backend's
`credential_process`, `cf-vault exec -p ci-state -- tofu plan` reads state from R2.

## 5. CI, noninteractive (User Story 5)

```sh
env -i PATH="$PATH" CLOUDFLARE_API_TOKEN=fake-token cf-vault exec -p ci-state -- true </dev/null
env -i PATH="$PATH" CLOUDFLARE_API_TOKEN=fake-token cf-vault exec -p personal -- true </dev/null   # OAuth profile, no broker: accepted
env -i PATH="$PATH" CF_VAULT_ID_TOKEN=fake.jwt.token cf-vault exec -p production -- true </dev/null
env -i PATH="$PATH" cf-vault exec -p production -- true </dev/null    # must exit 1 in under 5 s
```

Expected: the first three exit `0`, store untouched, no prompt; the last fails fast.

## 6. List (User Story 6) and secret hygiene

`cf-vault list --json`: every profile with a state, no credential material. Then, with sentinel
secrets (e.g. `SENTINEL-SECRET-123`) used throughout scenarios 1–5, grep stdout, stderr, the
config, `$HOME`, and temp dirs for the sentinels: zero hits (SC-004, SC-005).

## 7. Inherited-token override

`CLOUDFLARE_API_TOKEN=old cf-vault exec -p personal -- sh -c 'echo $CLOUDFLARE_API_TOKEN'` on a
terminal: prints the profile token (not `old`) and one stderr notice that never shows `old`.

## 8. Profile selection

```sh
CF_VAULT_PROFILE=personal cf-vault exec -- true          # env default works: exit 0
CF_VAULT_PROFILE=other cf-vault exec -p personal -- true # flag wins over the environment
cf-vault exec -p personal -p production -- true          # given twice: usage error, exit 2, command not run
cf-vault exec -- true                                    # no profile anywhere: exit 1, lists profiles
```

## Live checks (manual, release gate for the zero-configuration profile)

Run once with a real Cloudflare account and a registered OAuth client; see
[research.md](research.md) spikes S1–S4:

1. Browser sign-in at Cloudflare with the registered client, loopback redirect, PKCE.
2. An access token works as `CLOUDFLARE_API_TOKEN` for `curl` against `/client/v4/user/tokens/verify`
   or `/accounts/{id}`, and for `wrangler whoami`.
3. A refresh token is issued (`offline_access`) and refresh succeeds; record token lifetimes.
4. R2: confirm whether an OAuth session can derive temporary credentials; otherwise confirm the
   static-token path with Workers R2 Storage Write.
5. Broker: one real exchange against a deployed `cloudflare-sts` (policy and profiles are its
   concern).
