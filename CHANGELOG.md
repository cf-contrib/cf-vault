# Changelog

## [0.2.0](https://github.com/cf-contrib/cf-vault/compare/v0.1.1...v0.2.0) (2026-11-14)


### ⚠ BREAKING CHANGES

* rename `url` to `issuer` and `profile` to `scopes` in [<profile>.oauth2.exchange]. The broker must read `scope` (cloudflare-sts needs the matching change).

### Features

* name the exchange broker by issuer or endpoints, ask with scopes ([218971b](https://github.com/cf-contrib/cf-vault/commit/218971b1149488edead8131f6dea436b31a4849b))


### Bug Fixes

* report a renamed exchange key once, without follow-on errors ([daed161](https://github.com/cf-contrib/cf-vault/commit/daed1610023d9ca90adc22d7dece4e464a6963c9))

## [0.1.1](https://github.com/cf-contrib/cf-vault/compare/v0.1.0...v0.1.1) (2026-11-13)


### Bug Fixes

* keep CI, Nix and toolchain files out of the crate package ([1b9216a](https://github.com/cf-contrib/cf-vault/commit/1b9216ab21b74b76f05df4de10b1d40da2ff2731))

## 0.1.0 (2026-11-13)


### Features

* check the ID token's issuer, audience, expiry and sign-in nonce ([71f2e74](https://github.com/cf-contrib/cf-vault/commit/71f2e74409626f6d8e0bd88df7b088c2cea9cbbe))
* implement cf-vault CLI (OAuth, token exchange, R2, CI) ([85a4696](https://github.com/cf-contrib/cf-vault/commit/85a46963d1343100cff6a9f28ea028bf68ee79e0))
* R2 credentials from an OAuth session ([6e4dc46](https://github.com/cf-contrib/cf-vault/commit/6e4dc46ec9a2b1614a0d8b8d22ef1f0a11587bb7))
* require azp for multi-audience ID tokens and say what went wrong ([a3c1f17](https://github.com/cf-contrib/cf-vault/commit/a3c1f17ddae0597144ea9c71839e0032d967c091))

## Changelog
