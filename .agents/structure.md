# Project Structure

Single npm package — no workspaces, no monorepo tooling.

## Directory Layout

```
vouchr/
├── src/
│   ├── index.ts                     # Public entry point; everything exported here is public API
│   ├── error/                       # VouchrError, VouchrErrorCode, isVouchrError
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
| `src/error/`             | `VouchrError` (carries a `VouchrErrorCode` and the original failure as `cause`) and `isVouchrError`, which checks the `Symbol.for('vouchr.error')` marker rather than `instanceof`, so it still matches when two copies of the package are installed. Every error `verify` throws is a `VouchrError`. |
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
