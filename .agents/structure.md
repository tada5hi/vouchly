# Project Structure

Single npm package — no workspaces, no monorepo tooling.

## Directory Layout

```
vouchly/
├── src/
│   ├── index.ts                     # Public entry point; everything exported here is public API
│   ├── cache/                       # ITokenCache, MemoryTokenCache, hashToken
│   ├── discovery/                   # fetchProviderMetadata, ProviderMetadata
│   ├── error/                       # VouchlyError, VouchlyErrorCode, isVouchlyError
│   ├── introspection/               # introspect (RFC 7662)
│   ├── issuer/                      # Issuer, IntrospectionOptions, matchIssuer, selectIssuer
│   ├── key/                         # KeySource, staticKeys, jwks, discovery, cachedKeys, resolveVerificationKey
│   ├── token/                       # parseToken, isCompactToken, ParsedToken
│   └── verifier/                    # Verifier, createVerifier, assertCertificateBinding
├── test/
│   ├── unit/                        # Unit specs, one per src module (only files matched by the vitest include glob)
│   └── vitest.config.ts             # Vitest config — note: NOT in the project root
├── dist/                            # Build output (git-ignored, produced by tsdown)
├── .github/
│   ├── assets/
│   │   ├── logo.svg                 # README header logo (token segments + seal, animated once)
│   │   └── verify.svg               # README diagram of the verify() steps and their error codes
│   ├── actions/
│   │   ├── install/action.yml       # Composite action: setup-node + cache + npm ci
│   │   └── build/action.yml         # Composite action: cache dist/ by SHA + npm run build
│   ├── workflows/
│   │   ├── main.yml                 # CI: install -> build -> (lint, test)
│   │   └── release.yml              # release-please -> build -> publish via tada5hi/monoship
│   ├── ISSUE_TEMPLATE/              # Bug report / feature request forms
│   └── dependabot.yml               # Daily npm + github-actions updates, grouped by major/minor
├── .husky/                          # Git hooks dir (core.hooksPath); no hooks are committed
├── .agents/                         # Agent guides (this directory)
├── AGENTS.md                        # Agent entry point
├── CLAUDE.md                        # Manifest that loads AGENTS.md + .agents/*.md
├── tsconfig.json                    # extends @tada5hi/tsconfig; noEmit
├── tsdown.config.ts                 # Bundler config (esm, dts, sourcemap)
├── eslint.config.js                 # Flat config wrapping @tada5hi/eslint-config
├── commitlint.config.mjs            # extends @tada5hi/commitlint-config
├── release-please-config.json       # Release automation config
└── .release-please-manifest.json    # Current released version (source of truth for bumps)
```

## Module Responsibilities

| Module                   | Purpose                                                                                          |
|--------------------------|--------------------------------------------------------------------------------------------------|
| `src/index.ts`           | Sole entry point and barrel; re-exports every module folder below.                               |
| `src/cache/`             | Verification result cache. `ITokenCache` is the port (`get`, `set` with a TTL in seconds; a TTL <= 0 stores nothing), keyed by `hashToken`, the hex SHA-256 of the verifier's `cacheNamespace`, a NUL character and the raw token, so a token never sits in memory as a key. An entry stores the claims, the issuer's name, the source and, for a local token, the header `typ` and `alg`. `MemoryTokenCache` is the default: bounded by `max` (default 10000; anything but an integer >= 1 is a `TypeError`), LRU through `Map` insertion order, TTL checked on read, and it clones entries on the way in and out so a caller mutating a result cannot change what is cached. |
| `src/discovery/`         | OIDC discovery. `fetchProviderMetadata(issuer, fetch, { cacheMaxAge })` reads `<issuer>/.well-known/openid-configuration` (one trailing slash of the issuer stripped, 10 s timeout), requires the answer's `issuer` to equal the configured one (OIDC Discovery 4.3) and `jwks_uri` and `introspection_endpoint`, when present, to be URLs, and returns `{ issuer, jwks_uri?, introspection_endpoint? }`; the discovery key source requires `jwks_uri` (`KEY_UNAVAILABLE` without it), introspection only `introspection_endpoint`. Answers are memoised per `fetch` and issuer string for `cacheMaxAge` seconds (default 600) with one shared in-flight request; a failure is remembered per `fetch` and issuer for 30 seconds, during which calls fail fast without a request; failures are plain `Error`s, mapped by the caller. The issuer always comes from configuration, never from a token. |
| `src/error/`             | `VouchlyError` (carries a `VouchlyErrorCode` and the original failure as `cause`) and `isVouchlyError`, which checks the `Symbol.for('vouchly.error')` marker rather than `instanceof`, so it still matches when two copies of the package are installed. Every error `verify` throws is a `VouchlyError`. |
| `src/introspection/`     | RFC 7662. `introspect(token, issuer, fetch)` POSTs `token=<token>` (form-encoded, `accept: application/json`, 10 s timeout) to `introspection.endpoint`, else to the `introspection_endpoint` discovered for a string issuer (a function issuer without an endpoint fails without any fetch). `authorization` is either `{ clientId, clientSecret }`, sent as `Basic base64(formEncode(id):formEncode(secret))` (RFC 6749 2.3.1), or a function `({ retry }) => header` whose value is the header verbatim; after a 401 a function is called again with `retry: true` and the request repeated once (credentials are not retried). Non-2xx (status in the message and as `VouchlyError.status`, never the body), non-JSON, a missing endpoint and any thrown failure are `INTROSPECTION_FAILED` with the original as `cause`; `active !== true` is `TOKEN_INACTIVE`. It answers the response as claims and applies no claim rules itself. |
| `src/issuer/`            | The `Issuer` config type (and `IntrospectionOptions`): which `iss` it trusts (an exact string, or a function over the UNVERIFIED claims that only selects the config), its key source, audience, algorithms, `typ`, clock tolerance, required claims and an optional claims predicate. `matchIssuer` / `selectIssuer` pick the first config that trusts a token; a function matcher counts only when it returns exactly `true`, and one that throws does not match. |
| `src/key/`               | Key sources and the key policy. A `KeySource` is `(context) => Promise<CryptoKey \| JWK>`; `staticKeys` (jose `createLocalJWKSet`), `jwks(url)` (jose `createRemoteJWKSet`, one set per `fetch`, the verifier's `fetch` passed as `customFetch`), `discovery({ cacheMaxAge })` (the issuer's metadata, then one `jwks()` per discovered `jwks_uri`; a function issuer is refused as `KEY_UNAVAILABLE` before any fetch, since its only URL would be the token's own `iss`, and a metadata failure is `KEY_UNAVAILABLE` with the original as `cause`) and `cachedKeys(load, { key, ttl, timeout, max })` (per-key TTL, one shared in-flight load per key, a deadline after which the flight rejects and a late result is dropped, oldest-first eviction at `max`, an integer >= 1 or a `TypeError`, failures never cached). `resolveVerificationKey` is the only way a key reaches verification: it imports a JWK with `jwk.alg ?? header.alg`, refuses a symmetric key, an RSA key under 2048 bits and a JWK whose `use` is not `sig` (`policy.ts`, internal), and turns every failure into `KEY_UNAVAILABLE` with the original as `cause`. |
| `src/token/`             | Strict token parsing. `isCompactToken` accepts exactly three base64url segments (no padding, no whitespace); `parseToken` checks that first, then decodes header and claims with jose and maps any failure to `TOKEN_MALFORMED`. It verifies nothing: callers use it to pick an issuer before any key fetch. |
| `src/verifier/`          | `Verifier` (`createVerifier`). The constructor refuses, with a `TypeError`: no issuers, a function issuer with neither `keys` nor `verification: 'remote'`, two issuers sharing a name (an issuer's name is its `id`, else its index as a string, which is also what the cache entry records) and an `opaque` id naming no issuer; a string issuer without `keys` gets its own `discovery()`. Without `fetch` the verifier uses the module-level `defaultFetch` (which reads the global at call time), one function for all of them, so the per-`fetch` discovery memo and `jwks()` sets are shared between such verifiers; key caches still live on the `KeySource` instance. `verify(token, { certificateThumbprint })`: a token that is not a compact JWS is `TOKEN_MALFORMED` (or goes to the `opaque` issuer) before any hash, cache or key access; then `parseToken`; then the cache by `hashToken`; then issuer selection (`ISSUER_UNTRUSTED`, no fetch); then `resolveVerificationKey` and jose `jwtVerify` with `algorithms` defaulting to the ones the resolved key implies (a JWK without `alg` was imported with the header's `alg`, restricted to what its key type supports, so it is the header's choice among those; `Issuer.algorithms` pins it), `requiredClaims` `['exp']`, `clockTolerance` 0 and the exact `iss` for a string issuer. jose errors map to `TOKEN_EXPIRED`, `CLAIM_INVALID` (claim, `alg` not allowed, invalid JWT) and otherwise `SIGNATURE_INVALID`; a claims predicate that is not `true` or throws is `CLAIM_INVALID`. Results are cached until `exp` (a token without `exp` is not cached), a cache that throws counts as a miss, and a hit is held to this verifier's own rules (`readCache`): it is served only under the record an uncached verify would select (the opaque issuer for a non-JWT) with a matching `source`, else it is a miss; a local entry must still match the issuer (`ISSUER_UNTRUSTED`), carry the required claims and the `typ` (`CLAIM_INVALID`); every entry is refused as `TOKEN_EXPIRED` once `exp <= now - clockTolerance` (the TTL is computed to the millisecond, `exp - Date.now() / 1000`, but a cache may round it up) and passes `audience` and the claims predicate again; a local entry also records the header `alg` and must pass `Issuer.algorithms` and `nbf` under this verifier's `clockTolerance`. Those checks are a second line only: a hit skips the key source and the signature, so the constructor refuses a cache passed in without a `cacheNamespace` (and a namespace containing NUL), and one namespace must mean one issuer configuration (replicas of a service). Every result, cache hits included, is a `structuredClone`. `assertCertificateBinding(claims, thumbprint)` (RFC 8705) runs on every result, cache hits included: any `cnf` fails closed as `BINDING_MISMATCH` unless its `x5t#S256` is a non-empty string equal to the thumbprint; a thumbprint provider is only called for a bound token. Introspection (`verification: 'remote'`, and a token that is not a compact JWS when `opaque` names an issuer) goes through the protected `verifyIntrospection`: `introspect`, then the issuer's `audience` (some `aud` value must be accepted) and claims predicate; the result is cached for `min(exp - now, introspection.maxCacheTTL)` (no `exp`: `maxCacheTTL` alone; neither: not cached) and the binding runs on it like on any result, against the response's `cnf` and, for a compact token, the token's own unverified `cnf` as well (`bindingClaims`; an unverified claim may only add a requirement), cache hits included. |
| `test/vitest.config.ts`  | Test include glob and v8 coverage thresholds. Referenced explicitly by the npm scripts.            |
| `tsdown.config.ts`       | Bundles `src/index.ts` to ESM with declarations and sourcemaps.                                    |

## Key Dependencies

The one runtime dependency is **`jose`** (JWS decoding and verification, JWK import). Nothing else ships; `src/` imports no `node:*` module.

| Dev dependency                | Role                                                                 |
|-------------------------------|----------------------------------------------------------------------|
| `tsdown`                      | Bundler; emits `dist/index.mjs`, `dist/index.d.mts`, and sourcemaps  |
| `vitest`                      | Test runner                                                          |
| `@vitest/coverage-v8`         | Coverage provider; required by `npm run test:coverage`               |
| `typescript`                  | Type checking (`noEmit`) and declaration generation input            |
| `eslint` + `typescript-eslint`| Linting                                                              |
| `@tada5hi/eslint-config`      | Shared flat ESLint config                                            |
| `@tada5hi/tsconfig`           | Shared base `tsconfig`                                               |
| `@tada5hi/commitlint-config`  | Shared Conventional Commits rules                                    |
| `husky`                       | Installs the git hooks path via the `prepare` script                 |

## Package Exports

```json
{
    "main": "dist/index.mjs",
    "types": "dist/index.d.mts",
    "exports": {
        "./package.json": "./package.json",
        ".": {
            "types": "./dist/index.d.mts",
            "import": "./dist/index.mjs"
        }
    },
    "files": ["dist"]
}
```

- **ESM-only.** There is no `require` condition and no CJS output; `"type": "module"` is set. Do not add a CJS build unless a consumer explicitly needs one.
- Only `dist/` is published (`files`), so anything not reachable from `src/index.ts` never ships.
- `src/index.ts` is the single public surface: if a symbol is not exported there, it is internal. Add new modules under `src/` and re-export them from `index.ts`.

## Separation of Concerns

- **Library code** → `src/`
- **Tests** → `test/unit/` (one spec per `src/` module; the `describe` block names the module, e.g. `describe('src/token', ...)`)
- **Build / bundling** → `tsdown.config.ts`
- **Lint / style / commit rules** → shared `@tada5hi/*` configs, thinly wrapped by the local config files
- **CI, release, dependency updates** → `.github/`
