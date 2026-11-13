# Limitations

* **Cleanup is best effort after forced termination.** `SIGKILL` cannot be caught, so a broker
  token is not released if cf-vault is killed that way; it expires on its own. Keep lifetimes
  short.
* **Credentials are obtained before the command starts and are not renewed while it runs.** A
  broker token or R2 credentials can expire under a long command; `--ttl` asks for a longer
  lifetime (a broker caps it at the profile's maximum). Directly derived R2 credentials last 15
  minutes unless `--ttl` is given.
* **R2 credentials cannot be revoked early.** They expire. A `credential_process` helper does not
  pass the expiry on, so a run longer than their lifetime can fail to save Terraform state.
* **Cloudflare's own sign-in needs a client of your own for now.** The zero-configuration profile
  needs a Cloudflare OAuth client registered for cf-vault, which does not exist yet; see
  [Cloudflare OAuth](cloudflare-oauth.md).
* **Direct R2 needs a static API token.** An OAuth session cannot derive temporary R2 credentials
  without a broker.
* **No plaintext fallback.** Without a usable keychain, `login` and any command that needs a stored
  session fail with a clear error. Supply credentials through the environment instead.
* **The ID token's signature is not verified by cf-vault.** The token comes straight from the token
  endpoint over TLS and a broker verifies it on every exchange.
* **macOS and Linux only.**
