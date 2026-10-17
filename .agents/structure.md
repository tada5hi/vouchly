# Project Structure

Single npm package — no workspaces, no monorepo tooling.

## Directory Layout

```
vouchr/
├── src/
│   ├── index.ts                     # Public entry point; everything exported here is public API
│   ├── cache/                       # ITokenCache, MemoryTokenCache, hashToken
│   ├── discovery/                   # fetchProviderMetadata, ProviderMetadata
│   ├── error/                       # VouchrError, VouchrErrorCode, isVouchrError
│   ├── issuer/                      # Issuer, IntrospectionOptions (types)
│   ├── key/                         # KeySource, staticKeys, jwks, discovery, cachedKeys, resolveVerificationKey
│   └── token/                       # parseToken, isCompactToken, ParsedToken
├── test/
│   ├── unit/                        # Unit specs, one per src module (only files matched by the vitest include glob)
│   └── vitest.config.ts             # Vitest config — note: NOT in the project root
├── dist/                            # Build output (git-ignored, produced by tsdown)
├── .github/
│   ├── assets/
│   │   └── logo.svg             # README header logo (referenced by relative path)
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
| `src/cache/`             | Verification result cache. `ITokenCache` is the port (`get`, `set` with a TTL in seconds; a TTL <= 0 stores nothing), keyed by `hashToken`, the hex SHA-256 of the raw token, so a token never sits in memory as a key. `MemoryTokenCache` is the default: bounded by `max` (default 10000), LRU through `Map` insertion order, TTL checked on read, and it clones entries on the way in and out so a caller mutating a result cannot change what is cached. |
| `src/discovery/`         | OIDC discovery. `fetchProviderMetadata(issuer, fetch, { cacheMaxAge })` reads `<issuer>/.well-known/openid-configuration` (one trailing slash of the issuer stripped, 10 s timeout), requires the answer's `issuer` to equal the configured one (OIDC Discovery 4.3) and `jwks_uri` to be a URL, and returns `{ issuer, jwks_uri, introspection_endpoint? }`. Answers are memoised per `fetch` and issuer string for `cacheMaxAge` seconds (default 600) with one shared in-flight request; failures are not memoised and are plain `Error`s, mapped by the caller. The issuer always comes from configuration, never from a token. |
| `src/error/`             | `VouchrError` (carries a `VouchrErrorCode` and the original failure as `cause`) and `isVouchrError`, which checks the `Symbol.for('vouchr.error')` marker rather than `instanceof`, so it still matches when two copies of the package are installed. Every error `verify` throws is a `VouchrError`. |
| `src/issuer/`            | The `Issuer` config type (and `IntrospectionOptions`): which `iss` it trusts (an exact string, or a function over the UNVERIFIED claims that only selects the config), its key source, audience, algorithms, `typ`, clock tolerance, required claims and an optional claims predicate. |
| `src/key/`               | Key sources and the key policy. A `KeySource` is `(context) => Promise<CryptoKey \| JWK>`; `staticKeys` (jose `createLocalJWKSet`), `jwks(url)` (jose `createRemoteJWKSet`, one set per `fetch`, the verifier's `fetch` passed as `customFetch`), `discovery({ cacheMaxAge })` (the issuer's metadata, then one `jwks()` per discovered `jwks_uri`; a function issuer is refused as `KEY_UNAVAILABLE` before any fetch, since its only URL would be the token's own `iss`, and a metadata failure is `KEY_UNAVAILABLE` with the original as `cause`) and `cachedKeys(load, { key, ttl, timeout, max })` (per-key TTL, one shared in-flight load per key, a deadline after which the flight rejects and a late result is dropped, oldest-first eviction at `max`, failures never cached). `resolveVerificationKey` is the only way a key reaches verification: it imports a JWK with `jwk.alg ?? header.alg`, refuses a symmetric key, an RSA key under 2048 bits and a JWK whose `use` is not `sig` (`policy.ts`, internal), and turns every failure into `KEY_UNAVAILABLE` with the original as `cause`. |
| `src/token/`             | Strict token parsing. `isCompactToken` accepts exactly three base64url segments (no padding, no whitespace); `parseToken` checks that first, then decodes header and claims with jose and maps any failure to `TOKEN_MALFORMED`. It verifies nothing: callers use it to pick an issuer before any key fetch. |
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
