# cf-vault documentation

Which setup is yours?

```mermaid
flowchart TD
    A([Where does the credential come from?]) --> B{CI, with no keychain?}
    B -- yes --> C[Environment variables<br/>ci.md]
    B -- no --> D{A broker issues it?<br/>cloudflare-sts or another RFC 8693 broker}
    D -- yes --> E[An oauth2 profile with exchange<br/>broker.md]
    D -- no --> F{Your own identity provider,<br/>or Cloudflare's own sign-in?}
    F -- yes --> G[An oauth2 profile with issuer and client_id<br/>cloudflare-oauth.md]
    F -- no --> H[An api_token profile<br/>configuration.md]
```

| Guide | What it covers |
|-------|----------------|
| [Configuration](configuration.md) | Every key of `config.toml`, how an OAuth profile resolves, endpoint discovery, examples |
| [Commands](commands.md) | `login`, `exec`, `logout`, `list`, the variables the command receives and the exit statuses |
| [Broker](broker.md) | Trading your sign-in for short-lived Cloudflare credentials at a cloudflare-sts broker or another RFC 8693 broker; Cloudflare Access as the identity provider |
| [Cloudflare OAuth](cloudflare-oauth.md) | Signing in with Cloudflare's own OAuth through a client you register, what it can do and how it behaves |
| [R2](r2.md) | Temporary R2 credentials, and feeding Terraform's S3 backend |
| [CI](ci.md) | Running without a terminal or keychain |
| [Limitations](limitations.md) | What cf-vault does not do |
