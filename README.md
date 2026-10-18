<p align="center">
    <img src="https://raw.githubusercontent.com/tada5hi/vouchly/master/.github/assets/logo.svg" alt="" width="96" height="96">
</p>

<h1 align="center">vouchly</h1>

<p align="center">
    <strong>Verify OAuth2 and OIDC tokens against trusted issuers: JWT, introspection and certificate-bound tokens, on any Web runtime.</strong>
</p>

<p align="center">
    You list the issuers you trust. vouchly picks the right one per token, finds its key, checks the claims and tells you why a token was refused.
</p>

<p align="center">
    <a href="https://npmjs.com/package/vouchly"><img src="https://badge.fury.io/js/vouchly.svg" alt="npm version"></a>
    <a href="https://github.com/tada5hi/vouchly/actions/workflows/main.yml"><img src="https://github.com/tada5hi/vouchly/actions/workflows/main.yml/badge.svg" alt="CI"></a>
</p>

<p align="center">
    <a href="#why-vouchly">Why</a> ·
    <a href="#installation">Installation</a> ·
    <a href="#usage">Usage</a> ·
    <a href="#issuer-options">Options</a> ·
    <a href="#errors">Errors</a> ·
    <a href="#api">API</a> ·
    <a href="#notes">Notes</a>
</p>

---

## Why vouchly?

A service that accepts tokens from more than one place (your own identity provider, GitHub Actions, a partner's OIDC provider) ends up writing the same code each time: decode the token, look at `iss`, find the JWKS for that issuer, refuse a key that should never verify anything, check `aud` and `exp`, maybe ask an introspection endpoint instead, cache the answer, and turn a dozen library errors into something an HTTP handler can map. Each of those steps has a well-known way to get it wrong.

| Concern | Without it | With vouchly |
|---------|------------|-------------|
| Which issuer? | Read `iss` yourself and branch | An allowlist of `Issuer` configs; an unknown `iss` fails with `issuer_untrusted` before any request goes out |
| Where the keys come from | Wire `jwks_uri` per issuer by hand | `discovery()` reads it from the issuer's `/.well-known/openid-configuration`; `jwks()`, `staticKeys()` and `cachedKeys()` for everything else |
| Algorithm confusion | Hope the allowed algorithms are set everywhere | Symmetric keys and RSA keys under 2048 bits are refused; a JWK that names its `alg` decides the algorithm, one without is imported with the header's `alg`, restricted to what its key type supports, and `algorithms` pins it |
| Malformed input | Whatever the decoder tolerates | Exactly three base64url segments, no padding, no whitespace, checked before the cache or any key lookup |
| Opaque and revocable tokens | A second code path with its own HTTP client | `verification: 'remote'` per issuer (RFC 7662), with a cache bound you choose |
| Certificate-bound tokens | Compare `cnf.x5t#S256` yourself, and remember it on cache hits | RFC 8705 binding checked on every call, cache hits included, failing closed |
| Repeated verification | Cache the decoded payload and hope it expires | A bounded cache keyed by the token's SHA-256, never kept past `exp` |
| Errors | jose errors, `TypeError`s, fetch failures | One `VouchlyError` with one of nine codes, the original kept as `cause` |

The same verifier accepts tokens from GitHub Actions and from your own provider; each issuer keeps its own rules:

```ts
import { createVerifier } from 'vouchly';

const verifier = createVerifier({
    issuers: [
        {
            id: 'github',
            issuer: 'https://token.actions.githubusercontent.com',
            audience: 'https://api.example.com',
        },
        {
            id: 'internal',
            issuer: 'https://id.example.com',
            audience: 'api',
        },
    ],
});

const { claims, issuer } = await verifier.verify(token);
```

<p align="center">
    <img src="https://raw.githubusercontent.com/tada5hi/vouchly/master/.github/assets/verify.svg" alt="verify(token) parses the token strictly, looks up its SHA-256 in the token cache, selects a trusted issuer from the unverified iss claim, verifies the token locally with the issuer's key source or by RFC 7662 introspection, and finally checks the RFC 8705 certificate binding. A cache hit skips the key lookup and the signature, not the verifier's claim rules, then goes on to the binding check. Each step fails with its own VouchlyError code: token_malformed, issuer_untrusted, key_unavailable or signature_invalid or claim_invalid or introspection_failed, and binding_mismatch. Nothing is fetched before an issuer is selected." width="100%">
</p>

## Installation

```bash
npm install vouchly
```

- ESM only, with TypeScript declarations included.
- Node.js `>= 22`. The source uses Web APIs only (`fetch`, WebCrypto, `TextEncoder`) and imports no `node:*` module, so it also runs on other Web runtimes.
- One runtime dependency: [`jose`](https://github.com/panva/jose).

## Usage

### GitHub Actions OIDC tokens

A string `issuer` is matched exactly against `iss`, and its keys are found through OIDC discovery. A `claims` predicate adds rules of your own; it runs after the signature and the standard claims were checked, so it only ever sees verified claims.

```ts
import { createVerifier, isVouchlyError } from 'vouchly';

const verifier = createVerifier({
    issuers: [
        {
            id: 'github',
            issuer: 'https://token.actions.githubusercontent.com',
            audience: 'https://deploy.example.com',
            claims: (claims) => claims.repository === 'acme/website' &&
                claims.ref === 'refs/heads/main',
        },
    ],
});

try {
    const { claims } = await verifier.verify(token);
    console.log(`deploy requested by ${claims.actor}`);
} catch (e) {
    if (isVouchlyError(e)) {
        console.log(e.code); // e.g. 'claim_invalid'
    }

    throw e;
}
```

- The predicate must return `true`. Anything else, or a throw, fails as `claim_invalid`.
- `audience` is passed to jose: some `aud` value must be one of the configured ones.

### Many issuers behind one pattern

When issuers appear at runtime (one per tenant or realm), match `iss` with a function and supply the keys yourself. The function sees **unverified** claims: it only selects this config and never replaces verification. Because a function issuer has no fixed URL, `discovery()` refuses it, and the constructor requires a `keys` source.

```ts
import type { JWK } from 'jose';
import { cachedKeys, createVerifier } from 'vouchly';

const baseUrl = 'https://auth.example.com';

const verifier = createVerifier({
    issuers: [
        {
            id: 'realms',
            issuer: (claims) => typeof claims.iss === 'string' &&
                claims.iss.startsWith(`${baseUrl}/realms/`),
            keys: cachedKeys(
                async ({ token, fetch }) => {
                    const realm = String(token.claims.realm_id).toLowerCase();
                    const kid = String(token.header.kid).toLowerCase();
                    const response = await fetch(`${baseUrl}/realms/${encodeURIComponent(realm)}/jwks/${encodeURIComponent(kid)}`);
                    if (!response.ok) {
                        throw new Error(`The key endpoint answered ${response.status}.`);
                    }

                    return await response.json() as JWK;
                },
                {
                    key: ({ token }) => `${String(token.claims.realm_id)}:${String(token.header.kid)}`,
                    ttl: 300,
                },
            ),
        },
    ],
});
```

- The loader only builds URLs from your own `baseUrl`. Never fetch from a URL taken out of the token.
- `cachedKeys` shares one in-flight load per cache key, keeps a key for `ttl` seconds (default 300), gives up after `timeout` seconds (default 10) and holds at most `max` keys (default 100, an integer of at least 1). A failed load is never cached.
- Whatever a key source returns still passes the key policy: a JWK with `kty: oct`, a `use` other than `sig`, or an RSA key under 2048 bits fails as `key_unavailable`.

### Key sources

| Source | Use it for |
|--------|------------|
| `discovery({ cacheMaxAge })` | Default for a string `issuer`. Reads `jwks_uri` from `<issuer>/.well-known/openid-configuration`, which must name the same `issuer`. Metadata is reused for `cacheMaxAge` seconds (default 600); after a failed fetch the issuer is not asked again for 30 seconds, and keys fail fast as `key_unavailable` meanwhile. |
| `jwks(url, { cacheMaxAge, cooldownDuration, timeoutDuration })` | A known JWKS URL. Wraps jose's `createRemoteJWKSet`; the three options are milliseconds, as in jose. |
| `staticKeys(keys)` | Keys you ship with the service, as JWKs. |
| `cachedKeys(load, { key, ttl, timeout, max })` | A custom loader, with a per-key TTL and shared in-flight loads. |

A key source is any `(context) => Promise<CryptoKey | JWK>`; `context` carries the parsed token, the matched issuer and the verifier's `fetch`.

### Introspection

Set `verification: 'remote'` to ask the issuer about each token (RFC 7662) instead of checking a signature. This is the way to notice a revoked token before it expires, and the only way to accept opaque tokens.

```ts
import { createVerifier } from 'vouchly';

const verifier = createVerifier({
    issuers: [
        {
            id: 'id-provider',
            issuer: 'https://id.example.com',
            verification: 'remote',
            introspection: {
                authorization: { clientId: 'resource-server', clientSecret: process.env.CLIENT_SECRET! },
                maxCacheTTL: 30,
            },
        },
    ],
    opaque: 'id-provider',
});
```

- The endpoint is `introspection.endpoint`, else the `introspection_endpoint` discovered for a string `issuer`. A function issuer needs an explicit `endpoint`.
- `authorization` is either client credentials, sent as HTTP Basic, or a function returning the whole `Authorization` header value (for a bearer token of your own).
- `active` other than `true` fails as `token_inactive`; a failed request, a non-2xx answer or a body that is not a JSON object fails as `introspection_failed`.
- The issuer's `audience` and `claims` predicate apply to the introspection response too.
- `opaque` names the issuer that introspects tokens which are not JWTs at all. Without it, such a token fails as `token_malformed`.
- A result is cached for the shorter of `exp - now` and `maxCacheTTL` seconds; with neither, it is not cached.

### Certificate-bound tokens

A token carrying `cnf` is bound to a client certificate (RFC 8705). Pass the SHA-256 thumbprint of the certificate the caller presented, base64url encoded:

```ts
const { claims } = await verifier.verify(token, {
    certificateThumbprint: () => thumbprintOf(request),
});
```

- A token with `cnf` fails as `binding_mismatch` unless `cnf.x5t#S256` equals the thumbprint. That includes a `cnf` that carries no `x5t#S256` at all, such as a DPoP `jkt`.
- A function is only called for a bound token, so it costs nothing for the rest.
- The check runs on every call, also when the result comes from the cache.
- A JWT verified by introspection is held to its own `cnf` as well as the response's: the token's claims are unverified, so they can only add a requirement. When either carries a thumbprint, the presented one must match every thumbprint present.

### Caching

By default each verifier keeps its own `MemoryTokenCache` with up to 10000 entries (least recently used first out; `max` must be an integer of at least 1). Pass `cache: false` to turn it off, or your own `ITokenCache` to share results between processes, for example between replicas of one service. A cache you pass in needs a `cacheNamespace`, and every verifier using that namespace must have the same issuer configuration: a cache hit skips the key lookup and the signature check, so an entry is only as trustworthy as the configuration that wrote it.

```ts
import type { ITokenCache, TokenCacheEntry } from 'vouchly';
import { createVerifier } from 'vouchly';

declare const redis: {
    get(key: string): Promise<string | null>,
    set(key: string, value: string, options: { EX: number }): Promise<unknown>,
};

const cache: ITokenCache = {
    async get(key) {
        const value = await redis.get(`vouchly:${key}`);
        return value ? JSON.parse(value) as TokenCacheEntry : undefined;
    },
    async set(key, entry, ttl) {
        if (ttl > 0) {
            await redis.set(`vouchly:${key}`, JSON.stringify(entry), { EX: Math.ceil(ttl) });
        }
    },
};

const verifier = createVerifier({
    issuers: [{ issuer: 'https://id.example.com' }],
    cache,
    cacheNamespace: 'orders-api',
});
```

- The key is the hex SHA-256 of the verifier's `cacheNamespace` (which may not contain NUL), a NUL character and the token, so the token itself is never stored as a key.
- `ttl` is in seconds, fractional, and never runs past the token's `exp`. A local token without `exp` is not cached. A cache that keeps an entry longer (one that rounds `ttl` up, say) still cannot serve it: a hit at or after `exp` (beyond the issuer's `clockTolerance`) fails as `token_expired`.
- A cache that throws counts as a miss on `get` and is ignored on `set`; it never fails a verification.
- A cache hit skips the key lookup and the signature check, so it cannot apply this verifier's key source, and the introspection settings of the verifier that wrote the entry are the ones that counted. That is why one namespace means one configuration.
- As a second line, a hit is still held to the rules that need no key: it is served only under the issuer this verifier would select for the token, and only after this verifier's `audience`, `requiredClaims`, `typ`, `algorithms`, `nbf` (with its `clockTolerance`), `exp` and `claims` predicate passed on the cached entry. A rule that fails gives the same error code as an uncached verify.

## Issuer options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `id` | `string` | the issuer's index | Names the config. Required for `opaque`; must be unique. |
| `issuer` | `string \| (claims) => boolean` | | A string must equal `iss`. A function sees unverified claims and only selects the config; it matches only when it returns exactly `true`. |
| `keys` | `KeySource` | `discovery()` for a string issuer | Required for a function issuer verified locally. |
| `verification` | `'local' \| 'remote'` | `'local'` | Check the signature, or ask the introspection endpoint. |
| `introspection` | `{ endpoint?, authorization?, maxCacheTTL? }` | | See [Introspection](#introspection). `maxCacheTTL` is in seconds. |
| `audience` | `string \| string[]` | not checked | Some `aud` value must be in the list. |
| `algorithms` | `string[]` | what the resolved key implies | The key's own `alg` when the JWK names one. A JWK without `alg` is imported with the token header's `alg`, restricted to algorithms its key type supports (an RSA key can then verify `RS*` or `PS*`); set `algorithms` to pin it. |
| `typ` | `string` | not checked | The expected `typ` header, e.g. `at+jwt`. |
| `clockTolerance` | `number` | `0` | Seconds of leeway for `exp` and `nbf`. |
| `requiredClaims` | `string[]` | `['exp']` | Claims that must be present. |
| `claims` | `(claims) => boolean \| Promise<boolean>` | | Your own rules over the verified claims. |

The verifier itself takes `issuers`, `cache` (`ITokenCache` or `false`), `cacheNamespace` (see [Caching](#caching)), `fetch` (defaults to the global `fetch`) and `opaque` (the `id` of the issuer that introspects non-JWT tokens). The constructor throws a `TypeError` for a configuration that cannot work: no issuers, a duplicate `id`, a function issuer verified locally without `keys`, or an `opaque` id that names no issuer.

## Errors

Every error `verify` throws is a `VouchlyError` with a `code`. The underlying error, when there is one, is kept as `cause`.

| Code | When |
|------|------|
| `token_malformed` | Not exactly three base64url segments, or a header or payload that is not a JSON object. |
| `token_expired` | `exp` is in the past (beyond `clockTolerance`). |
| `token_inactive` | Introspection answered `active` other than `true`. |
| `issuer_untrusted` | No configured issuer matches `iss`. |
| `key_unavailable` | Discovery or the key fetch failed, no key matches the `kid`, or the key policy refused the key. |
| `signature_invalid` | The signature does not verify. |
| `claim_invalid` | `aud`, `iss`, `typ`, `nbf`, a required claim, the algorithm or the `claims` predicate. |
| `introspection_failed` | The introspection request failed, answered non-2xx, or did not answer a JSON object. |
| `binding_mismatch` | The token is certificate-bound and the presented thumbprint does not match. |

Use `isVouchlyError(error)` rather than `instanceof`: it checks a `Symbol.for('vouchly.error')` marker, so it still matches when two copies of vouchly are installed.

## API

| Export | Kind | Purpose |
|--------|------|---------|
| `createVerifier(options)`, `Verifier` | function, class | The verifier; `verify(token, options?)` answers `{ claims, issuer, source }`. |
| `discovery`, `jwks`, `staticKeys`, `cachedKeys` | functions | Key sources, see [Key sources](#key-sources). |
| `resolveVerificationKey(source, context)` | function | Runs a key source through the key policy; what the verifier uses. |
| `fetchProviderMetadata(issuer, fetch, options?)` | function | Reads and checks an issuer's OIDC discovery document. |
| `introspect(token, issuer, fetch)` | function | One RFC 7662 request; applies no claim rules of its own. |
| `assertCertificateBinding(claims, thumbprint)` | function | The RFC 8705 check on its own. |
| `MemoryTokenCache`, `ITokenCache`, `hashToken` | class, interface, function | The default cache, the cache port and the key derivation. |
| `parseToken`, `isCompactToken` | functions | Strict parsing without verification. |
| `matchIssuer`, `selectIssuer` | functions | The issuer allowlist on its own. |
| `VouchlyError`, `VouchlyErrorCode`, `isVouchlyError` | class, enum, function | Errors. |

## Notes

- **A locally verified token is valid until `exp`.** A signature cannot tell that the token was revoked. If revocation must take effect sooner, use introspection with a short `maxCacheTTL`, or keep access tokens short-lived.
- **Nothing is fetched from a URL inside the token.** Discovery, JWKS and introspection URLs come from your configuration; a function issuer therefore needs its own key source or an explicit introspection endpoint.
- **Keys stay in process memory.** `CryptoKey`s cannot be serialised, so key caches (`jwks`, `discovery`, `cachedKeys`) are per process even when the token cache is shared.
- **Key caches live on the key source instance.** Each `discovery()`, `jwks()` and `cachedKeys()` call creates its own cache, and a string issuer without `keys` gets a `discovery()` of its own per verifier. Discovery metadata is shared by every verifier using the default `fetch` (or the same `fetch` function), but the JWKS behind it is not. If you build verifiers at runtime (one per request, per tenant), create the key source once and pass the same instance to each of them, or every verifier fetches the keys again.
- **Results are copies.** Every result, including a cache hit, is a fresh `structuredClone`; changing it does not change the cached entry.
- **No permission model.** vouchly answers whether a token is genuine and which issuer it came from. Deciding what the caller may do is up to you.

## Contributing

Before starting to work on a pull request, it is important to review the guidelines for
[contributing](./CONTRIBUTING.md) and the [code of conduct](./CODE_OF_CONDUCT.md).
These guidelines will help to ensure that contributions are made effectively and are accepted.

## License

Made with 💚

Published under [Apache-2.0 License](./LICENSE).
