# Broker

A [cloudflare-sts](https://github.com/cf-contrib/cloudflare-sts) broker holds the only long-lived
Cloudflare token. You sign in through your identity provider, cf-vault trades your ID token at the
broker (RFC 8693 token exchange), and the broker decides, from its policy, what you get: a
short-lived, narrowly scoped API token, temporary R2 credentials for one bucket, or both.
cf-vault never needs a Cloudflare token of its own.

```toml
[production]
type = "oauth2"
account_id = "xyz789"

[production.oauth2.exchange]
url = "https://cloudflare-sts-api.example.com"
profile = "infra-admins:tofu-plan"
```

```bash
cf-vault login -p production
cf-vault exec -p production --ttl 30m -- tofu plan
```

## What happens

1. **login** reads the broker's metadata (`/.well-known/oauth-authorization-server`) to learn which
   identity provider people sign in with and as which client, then runs the browser sign-in there.
2. **exec** renews the ID token if it is about to expire, sends it to the broker with the profile
   you named, and gives the command what comes back. When the command ends, the API token is
   revoked at the broker.

The broker's contract is documented in its own repository; cf-vault follows it as is.

## Checks

- The broker's metadata must name the URL you configured as its issuer, and its endpoints must be
  on its own host.
- The ID token from the provider is checked before it is stored or used: issuer, audience (and
  `azp` when there are several), expiry and, at sign-in, the nonce cf-vault sent. The signature is
  not checked by cf-vault: the broker verifies it on every exchange.
- If the broker answers for a different account than the profile's `account_id`, cf-vault releases
  what was issued and does not start the command.
- A refused exchange shows the broker's reason and never a token; `503` is retried once.

## Cloudflare Access as the identity provider

An Access for SaaS OIDC application (a public client with PKCE and the redirect
`http://127.0.0.1:8250/callback`) works as the provider. Things to know:

- Access's ID tokens last **5 minutes**. For a sign-in that lasts, give the application a refresh
  token lifetime, and ask for the `offline_access` scope: Access accepts it but does not list it
  in its metadata, so cf-vault does not ask unless you do.
- Access has no revocation endpoint: `logout` removes the local session only.
- The application's policy decides who can sign in; the broker's profiles decide what each person
  gets.

```toml
[production.oauth2]
scopes = ["openid", "email", "offline_access"]
```

## Lifetime

`--ttl` (for example `10m` or `1h`, at least one minute) is passed to the broker, which caps it at
the profile's maximum. Without it the profile's own lifetime applies. A running command is not
renewed: pick a lifetime that covers it.
