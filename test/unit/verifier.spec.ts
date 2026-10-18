import type { JWK, JWTPayload } from 'jose';
import {
    SignJWT,
    base64url,
    errors,
    exportJWK,
    generateKeyPair,
} from 'jose';
import {
    afterEach,
    describe,
    expect,
    it,
    vi,
} from 'vitest';
import type { Issuer, KeySource } from '../../src';
import {
    MemoryTokenCache,
    Verifier,
    VouchrErrorCode,
    createVerifier,
    isVouchrError,
    staticKeys,
} from '../../src';

const ISSUER = 'https://issuer.example';

type SigningKey = {
    privateKey: CryptoKey,
    jwk: JWK,
};

async function createSigningKey(kid: string) : Promise<SigningKey> {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
    const jwk = await exportJWK(publicKey);

    return {
        privateKey,
        jwk: {
            ...jwk,
            kid,
            alg: 'RS256',
            use: 'sig',
        },
    };
}

type SignOptions = {
    claims?: JWTPayload,
    kid?: string,
    typ?: string,
    exp?: number | string | false,
    nbf?: number,
};

async function sign(key: SigningKey, options: SignOptions = {}) : Promise<string> {
    const jwt = new SignJWT({
        sub: 'user', 
        iss: ISSUER, 
        ...options.claims, 
    })
        .setProtectedHeader({
            alg: 'RS256',
            kid: options.kid ?? key.jwk.kid,
            ...(options.typ ? { typ: options.typ } : {}),
        })
        .setIssuedAt();

    if (options.exp !== false) {
        jwt.setExpirationTime(options.exp ?? '1h');
    }

    if (typeof options.nbf !== 'undefined') {
        jwt.setNotBefore(options.nbf);
    }

    return jwt.sign(key.privateKey);
}

function countingKeys(keys: JWK[]) : { source: KeySource, calls: () => number } {
    const inner = staticKeys(keys);
    let count = 0;

    return {
        source: async (context) => {
            count++;
            return inner(context);
        },
        calls: () => count,
    };
}

async function expectCode(promise: Promise<unknown>, code: VouchrErrorCode) : Promise<unknown> {
    let error : unknown;
    try {
        await promise;
    } catch (e) {
        error = e;
    }

    expect(isVouchrError(error)).toBe(true);
    expect((error as { code: VouchrErrorCode }).code).toBe(code);

    return error;
}

const now = () => Math.floor(Date.now() / 1000);

describe('src/verifier', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('should verify a valid token locally', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({
            issuers: [{
                id: 'main', 
                issuer: ISSUER, 
                keys: staticKeys([key.jwk]), 
            }], 
        });

        const result = await verifier.verify(await sign(key));

        expect(result.claims.sub).toBe('user');
        expect(result.source).toBe('local');
        expect(result.issuer.id).toBe('main');
        expect(verifier).toBeInstanceOf(Verifier);
    });

    it('should refuse an untrusted issuer without touching the key source', async () => {
        const key = await createSigningKey('k1');
        const keys = countingKeys([key.jwk]);
        const verifier = createVerifier({ issuers: [{ issuer: ISSUER, keys: keys.source }] });

        await expectCode(
            verifier.verify(await sign(key, { claims: { iss: 'https://other.example' } })),
            VouchrErrorCode.ISSUER_UNTRUSTED,
        );
        expect(keys.calls()).toBe(0);
    });

    it('should select a function issuer by an unverified claim', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({
            issuers: [
                {
                    id: 'a', 
                    issuer: (claims) => claims.realm_id === 'a', 
                    keys: staticKeys([key.jwk]), 
                },
                {
                    id: 'b', 
                    issuer: (claims) => claims.realm_id === 'b', 
                    keys: staticKeys([key.jwk]), 
                },
            ],
        });

        const result = await verifier.verify(await sign(key, { claims: { iss: 'https://any.example', realm_id: 'b' } }));
        expect(result.issuer.id).toBe('b');
    });

    it('should refuse a function issuer that does not return true', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({
            issuers: [
                { issuer: () => { throw new Error('boom'); }, keys: staticKeys([key.jwk]) },
                { issuer: () => 'yes' as unknown as boolean, keys: staticKeys([key.jwk]) },
            ],
        });

        await expectCode(verifier.verify(await sign(key)), VouchrErrorCode.ISSUER_UNTRUSTED);
    });

    it('should enforce the claim rules', async () => {
        const key = await createSigningKey('k1');
        const base : Issuer = {
            issuer: ISSUER,
            keys: staticKeys([key.jwk]),
            audience: 'api',
            typ: 'at+jwt',
        };
        const verifier = createVerifier({ issuers: [base], cache: false });

        await expectCode(
            verifier.verify(await sign(key, { claims: { aud: 'other' }, typ: 'at+jwt' })),
            VouchrErrorCode.CLAIM_INVALID,
        );
        await expectCode(
            verifier.verify(await sign(key, { claims: { aud: 'api' }, typ: 'JWT' })),
            VouchrErrorCode.CLAIM_INVALID,
        );
        await expectCode(
            verifier.verify(await sign(key, {
                claims: { aud: 'api' }, 
                typ: 'at+jwt', 
                nbf: now() + 600, 
            })),
            VouchrErrorCode.CLAIM_INVALID,
        );
        await expectCode(
            verifier.verify(await sign(key, {
                claims: { aud: 'api' }, 
                typ: 'at+jwt', 
                exp: now() - 60, 
            })),
            VouchrErrorCode.TOKEN_EXPIRED,
        );
        await expectCode(
            verifier.verify(await sign(key, {
                claims: { aud: 'api' }, 
                typ: 'at+jwt', 
                exp: false, 
            })),
            VouchrErrorCode.CLAIM_INVALID,
        );

        const result = await verifier.verify(await sign(key, { claims: { aud: 'api' }, typ: 'at+jwt' }));
        expect(result.claims.aud).toBe('api');
    });

    it('should honour the clock tolerance', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({
            issuers: [{
                issuer: ISSUER, 
                keys: staticKeys([key.jwk]), 
                clockTolerance: 60, 
            }], 
        });

        const result = await verifier.verify(await sign(key, { nbf: now() + 30 }));
        expect(result.claims.sub).toBe('user');
    });

    it('should refuse a token signed by another key', async () => {
        const key = await createSigningKey('k1');
        const other = await createSigningKey('k1');
        const verifier = createVerifier({ issuers: [{ issuer: ISSUER, keys: staticKeys([key.jwk]) }] });

        await expectCode(verifier.verify(await sign(other)), VouchrErrorCode.SIGNATURE_INVALID);
    });

    it('should not accept alg none', async () => {
        const key = await createSigningKey('k1');
        // A key source that answers whatever the header asks for, so jose
        // itself has to refuse the algorithm.
        const verifier = createVerifier({ issuers: [{ issuer: ISSUER, keys: async () => key.jwk }] });

        const header = base64url.encode(JSON.stringify({ alg: 'none', kid: 'k1' }));
        const payload = base64url.encode(JSON.stringify({
            sub: 'user', 
            iss: ISSUER, 
            exp: now() + 3600, 
        }));
        // An empty signature segment is not a compact JWS at all.
        await expectCode(verifier.verify(`${header}.${payload}.`), VouchrErrorCode.TOKEN_MALFORMED);

        // A non-empty one gets as far as jose, which refuses the algorithm.
        const error = await expectCode(verifier.verify(`${header}.${payload}.AAAA`), VouchrErrorCode.CLAIM_INVALID);
        expect((error as Error).cause).toBeInstanceOf(errors.JOSEAlgNotAllowed);
    });

    it('should refuse when the claims predicate does not pass', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({
            issuers: [
                {
                    id: 'a', 
                    issuer: ISSUER, 
                    keys: staticKeys([key.jwk]), 
                    claims: async () => false, 
                },
            ],
        });
        await expectCode(verifier.verify(await sign(key)), VouchrErrorCode.CLAIM_INVALID);

        const throwing = createVerifier({
            issuers: [
                {
                    issuer: ISSUER, 
                    keys: staticKeys([key.jwk]), 
                    claims: () => { throw new Error('nope'); }, 
                },
            ],
        });
        await expectCode(throwing.verify(await sign(key)), VouchrErrorCode.CLAIM_INVALID);
    });

    it('should serve a second verify from the cache', async () => {
        const key = await createSigningKey('k1');
        const keys = countingKeys([key.jwk]);
        const verifier = createVerifier({
            issuers: [{
                id: 'main', 
                issuer: ISSUER, 
                keys: keys.source, 
            }], 
        });
        const token = await sign(key);

        await verifier.verify(token);
        const second = await verifier.verify(token);

        expect(keys.calls()).toBe(1);
        expect(second.issuer.id).toBe('main');
        expect(second.source).toBe('local');
    });

    it('should not serve another audience from a shared cache', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const a = createVerifier({
            issuers: [{
                id: 'main',
                issuer: ISSUER,
                keys: staticKeys([key.jwk]),
                audience: 'service-a',
            }],
            cache,
            cacheNamespace: 'shared',
        });
        const b = createVerifier({
            issuers: [{
                id: 'main',
                issuer: ISSUER,
                keys: staticKeys([key.jwk]),
                audience: 'service-b',
            }],
            cache,
            cacheNamespace: 'shared',
        });
        const token = await sign(key, { claims: { aud: 'service-a' } });

        await a.verify(token);
        await expectCode(b.verify(token), VouchrErrorCode.CLAIM_INVALID);
    });

    it('should not serve another issuer from a shared cache', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const a = createVerifier({
            issuers: [{ issuer: ISSUER, keys: staticKeys([key.jwk]) }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const b = createVerifier({
            issuers: [{ issuer: 'https://other.example', keys: staticKeys([key.jwk]) }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const token = await sign(key);

        await a.verify(token);
        await expectCode(b.verify(token), VouchrErrorCode.ISSUER_UNTRUSTED);
    });

    it('should re-apply the typ, required claims and claims predicate on a cache hit', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const base : Issuer = {
            id: 'main',
            issuer: ISSUER,
            keys: staticKeys([key.jwk]),
        };
        const a = createVerifier({
            issuers: [base], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const token = await sign(key, { typ: 'JWT' });
        await a.verify(token);

        const typ = createVerifier({
            issuers: [{ ...base, typ: 'at+jwt' }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        await expectCode(typ.verify(token), VouchrErrorCode.CLAIM_INVALID);

        const required = createVerifier({
            issuers: [{ ...base, requiredClaims: ['exp', 'jti'] }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        await expectCode(required.verify(token), VouchrErrorCode.CLAIM_INVALID);

        const predicate = createVerifier({
            issuers: [{ ...base, claims: () => false }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        await expectCode(predicate.verify(token), VouchrErrorCode.CLAIM_INVALID);

        const same = createVerifier({
            issuers: [{ ...base, typ: 'jwt' }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        expect((await same.verify(token)).claims.sub).toBe('user');
    });

    it('should keep namespaced verifiers apart in a shared cache', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const keysA = countingKeys([key.jwk]);
        const keysB = countingKeys([key.jwk]);
        const a = createVerifier({
            issuers: [{ issuer: ISSUER, keys: keysA.source }], 
            cache, 
            cacheNamespace: 'a', 
        });
        const b = createVerifier({
            issuers: [{ issuer: ISSUER, keys: keysB.source }], 
            cache, 
            cacheNamespace: 'b', 
        });
        const token = await sign(key);

        await a.verify(token);
        await b.verify(token);
        await b.verify(token);

        expect(keysA.calls()).toBe(1);
        expect(keysB.calls()).toBe(1);
    });

    it('should require a cacheNamespace for a cache passed in', () => {
        const cache = new MemoryTokenCache();
        const issuers : Issuer[] = [{ issuer: ISSUER, keys: staticKeys([]) }];

        expect(() => createVerifier({ issuers, cache })).toThrow(TypeError);
        expect(() => createVerifier({
            issuers, 
            cache, 
            cacheNamespace: '', 
        })).toThrow(TypeError);
        expect(() => createVerifier({
            issuers, 
            cache, 
            cacheNamespace: 'api', 
        })).not.toThrow();
        expect(() => createVerifier({ issuers })).not.toThrow();
        expect(() => createVerifier({ issuers, cache: false })).not.toThrow();
    });

    it('should refuse a cacheNamespace containing NUL', () => {
        expect(() => createVerifier({
            issuers: [{ issuer: ISSUER, keys: staticKeys([]) }],
            cache: new MemoryTokenCache(),
            cacheNamespace: 'a\u0000x',
        })).toThrow(TypeError);
    });

    it('should re-apply the algorithm pin on a cache hit', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const base : Issuer = {
            id: 'main', 
            issuer: ISSUER, 
            keys: staticKeys([key.jwk]), 
        };
        const a = createVerifier({
            issuers: [base], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const b = createVerifier({
            issuers: [{ ...base, algorithms: ['PS256'] }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const token = await sign(key);

        await a.verify(token);
        await expectCode(b.verify(token), VouchrErrorCode.CLAIM_INVALID);
    });

    it('should re-apply nbf with the reading verifier\'s clock tolerance on a cache hit', async () => {
        const key = await createSigningKey('k1');
        const cache = new MemoryTokenCache();
        const base : Issuer = {
            id: 'main', 
            issuer: ISSUER, 
            keys: staticKeys([key.jwk]), 
        };
        const a = createVerifier({
            issuers: [{ ...base, clockTolerance: 120 }], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const b = createVerifier({
            issuers: [base], 
            cache, 
            cacheNamespace: 'shared', 
        });
        const token = await sign(key, { nbf: Math.floor(Date.now() / 1000) + 60 });

        await a.verify(token);
        await expectCode(b.verify(token), VouchrErrorCode.CLAIM_INVALID);
    });

    it('should refuse a cached local token at its exp second', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(1_800_000_000_500);

        const key = await createSigningKey('k1');
        const verifier = createVerifier({ issuers: [{ issuer: ISSUER, keys: staticKeys([key.jwk]) }] });
        const token = await sign(key, { exp: 1_800_000_010 });

        await verifier.verify(token);

        vi.setSystemTime(1_800_000_010_000);
        await expectCode(verifier.verify(token), VouchrErrorCode.TOKEN_EXPIRED);
    });

    it('should refuse an expired token served by a cache that rounds its ttl up', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(1_800_000_000_500);

        const key = await createSigningKey('k1');
        const keys = countingKeys([key.jwk]);
        const memory = new MemoryTokenCache();
        const verifier = createVerifier({
            issuers: [{ issuer: ISSUER, keys: keys.source }],
            cacheNamespace: 'api',
            cache: {
                get: (k) => memory.get(k),
                set: (k, entry, ttl) => memory.set(k, entry, Math.ceil(ttl)),
            },
        });
        const token = await sign(key, { exp: 1_800_000_010 });

        await verifier.verify(token);

        vi.setSystemTime(1_800_000_010_000);
        await expectCode(verifier.verify(token), VouchrErrorCode.TOKEN_EXPIRED);
        expect(keys.calls()).toBe(1);
    });

    it('should refuse a padded variant before any key fetch or cache write', async () => {
        const key = await createSigningKey('k1');
        const keys = countingKeys([key.jwk]);
        const writes : string[] = [];
        const memory = new MemoryTokenCache();
        const verifier = createVerifier({
            issuers: [{ issuer: ISSUER, keys: keys.source }],
            cacheNamespace: 'api',
            cache: {
                get: (k) => memory.get(k),
                set: async (k, entry, ttl) => {
                    writes.push(k);
                    await memory.set(k, entry, ttl);
                },
            },
        });
        const token = await sign(key);

        await expectCode(verifier.verify(`${token}==`), VouchrErrorCode.TOKEN_MALFORMED);
        await expectCode(verifier.verify(` ${token}`), VouchrErrorCode.TOKEN_MALFORMED);
        expect(keys.calls()).toBe(0);
        expect(writes).toHaveLength(0);

        await verifier.verify(token);
        expect(writes).toHaveLength(1);
    });

    it('should not cache a token without exp', async () => {
        const key = await createSigningKey('k1');
        const keys = countingKeys([key.jwk]);
        const verifier = createVerifier({
            issuers: [{
                issuer: ISSUER, 
                keys: keys.source, 
                requiredClaims: [], 
            }], 
        });
        const token = await sign(key, { exp: false });

        await verifier.verify(token);
        await verifier.verify(token);
        expect(keys.calls()).toBe(2);
    });

    it('should map a key source failure to KEY_UNAVAILABLE', async () => {
        const key = await createSigningKey('k1');
        const verifier = createVerifier({ issuers: [{ issuer: ISSUER, keys: staticKeys([key.jwk]) }] });

        await expectCode(verifier.verify(await sign(key, { kid: 'unknown' })), VouchrErrorCode.KEY_UNAVAILABLE);
    });

    it('should refuse misconfiguration at construction', () => {
        expect(() => createVerifier({ issuers: [] })).toThrow(TypeError);
        expect(() => createVerifier({ issuers: [{ issuer: () => true }] })).toThrow(TypeError);
        expect(() => createVerifier({ issuers: [{ id: 'a', issuer: ISSUER }, { id: 'a', issuer: 'https://other.example' }] })).toThrow(TypeError);
        expect(() => createVerifier({ issuers: [{ id: 'a', issuer: ISSUER }], opaque: 'b' })).toThrow(TypeError);
        expect(() => new Verifier({ issuers: [] })).toThrow(TypeError);

        expect(() => createVerifier({ issuers: [{ issuer: () => true, verification: 'remote' }] })).not.toThrow();
    });
});
