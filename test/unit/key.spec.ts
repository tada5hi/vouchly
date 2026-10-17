import type { JWK } from 'jose';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import {
    describe,
    expect,
    it,
} from 'vitest';
import type { KeySourceContext } from '../../src';
import {
    VouchrErrorCode,
    cachedKeys,
    isVouchrError,
    jwks,
    parseToken,
    resolveVerificationKey,
    staticKeys,
} from '../../src';

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

async function createContext(
    key: SigningKey,
    options: { fetch?: typeof fetch, alg?: string } = {},
) : Promise<KeySourceContext> {
    const token = await new SignJWT({ sub: 'user' })
        .setProtectedHeader({ alg: options.alg ?? 'RS256', kid: key.jwk.kid })
        .setIssuer('https://issuer.example')
        .setExpirationTime('1h')
        .sign(key.privateKey);

    return {
        token: parseToken(token),
        issuer: { issuer: 'https://issuer.example' },
        fetch: options.fetch ?? (async () => {
            throw new Error('fetch must not be called');
        }),
    };
}

async function expectKeyUnavailable(promise: Promise<unknown>, message?: string) {
    let error : unknown;
    try {
        await promise;
    } catch (e) {
        error = e;
    }

    expect(isVouchrError(error)).toBe(true);
    expect((error as { code: string }).code).toEqual(VouchrErrorCode.KEY_UNAVAILABLE);
    if (message) {
        expect((error as Error).message).toContain(message);
    }
}

function wait(ms: number) {
    return new Promise((resolve) => { setTimeout(resolve, ms); });
}

describe('src/key', () => {
    describe('staticKeys', () => {
        it('should resolve the key matching the token kid', async () => {
            const a = await createSigningKey('a');
            const b = await createSigningKey('b');

            const context = await createContext(b);
            const key = await resolveVerificationKey(staticKeys([a.jwk, b.jwk]), context);

            const expected = await exportJWK(key);
            expect(expected.n).toEqual(b.jwk.n);
        });

        it('should fail for an unknown kid', async () => {
            const a = await createSigningKey('a');
            const b = await createSigningKey('b');

            const context = await createContext(b);
            await expectKeyUnavailable(resolveVerificationKey(staticKeys([a.jwk]), context));
        });
    });

    describe('policy', () => {
        it('should reject a symmetric key', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            await expectKeyUnavailable(resolveVerificationKey(async () => ({
                kty: 'oct',
                k: 'c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA',
                alg: 'HS256',
            }), context));
        });

        it('should reject an RSA key under 2048 bits', async () => {
            const pair = await crypto.subtle.generateKey(
                {
                    name: 'RSASSA-PKCS1-v1_5',
                    modulusLength: 1024,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256',
                },
                true,
                ['sign', 'verify'],
            );
            const weak = await exportJWK(pair.publicKey);

            const key = await createSigningKey('a');
            const context = await createContext(key);

            await expectKeyUnavailable(
                resolveVerificationKey(async () => ({ ...weak, alg: 'RS256' }), context),
                '1024',
            );
        });

        it('should reject a key whose use is not sig', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            await expectKeyUnavailable(resolveVerificationKey(async () => ({ ...key.jwk, use: 'enc' }), context));
        });

        it('should accept a CryptoKey returned by a source', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            const imported = await resolveVerificationKey(async () => key.jwk, context);
            const resolved = await resolveVerificationKey(async () => imported, context);
            expect(resolved).toBe(imported);
        });

        it('should wrap a failing source', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            const cause = new TypeError('boom');
            let error : unknown;
            try {
                await resolveVerificationKey(async () => { throw cause; }, context);
            } catch (e) {
                error = e;
            }

            expect((error as { code: string }).code).toEqual(VouchrErrorCode.KEY_UNAVAILABLE);
            expect((error as Error).cause).toBe(cause);
        });
    });

    describe('cachedKeys', () => {
        it('should load once for two calls with the same key', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            let loads = 0;
            const source = cachedKeys(async () => {
                loads++;
                return key.jwk;
            }, { key: (ctx) => ctx.token.header.kid as string });

            await resolveVerificationKey(source, context);
            await resolveVerificationKey(source, context);

            expect(loads).toEqual(1);
        });

        it('should share one load between concurrent misses', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            let loads = 0;
            const source = cachedKeys(async () => {
                loads++;
                await wait(10);
                return key.jwk;
            }, { key: () => 'a' });

            await Promise.all([
                resolveVerificationKey(source, context),
                resolveVerificationKey(source, context),
            ]);

            expect(loads).toEqual(1);
        });

        it('should reject a load slower than the timeout and load again on the next call', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            let loads = 0;
            const source = cachedKeys(async () => {
                loads++;
                if (loads === 1) {
                    await wait(200);
                }

                return key.jwk;
            }, { key: () => 'a', timeout: 0.02 });

            await expectKeyUnavailable(resolveVerificationKey(source, context));
            await resolveVerificationKey(source, context);

            expect(loads).toEqual(2);
        });

        it('should evict the oldest entry beyond max', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            const loads : string[] = [];
            let current = 'a';
            const source = cachedKeys(async () => {
                loads.push(current);
                return key.jwk;
            }, { key: () => current, max: 1 });

            await resolveVerificationKey(source, context);
            current = 'b';
            await resolveVerificationKey(source, context);
            current = 'a';
            await resolveVerificationKey(source, context);

            expect(loads).toEqual(['a', 'b', 'a']);
        });

        it('should not cache a failed load', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key);

            let loads = 0;
            const source = cachedKeys(async () => {
                loads++;
                if (loads === 1) {
                    throw new Error('unavailable');
                }

                return key.jwk;
            }, { key: () => 'a' });

            await expectKeyUnavailable(resolveVerificationKey(source, context));
            await resolveVerificationKey(source, context);

            expect(loads).toEqual(2);
        });

        it('should reject invalid options', () => {
            const load = async () => ({ kty: 'RSA' });
            const key = () => 'a';

            expect(() => cachedKeys(load, { key, ttl: -1 })).toThrow(TypeError);
            expect(() => cachedKeys(load, { key, ttl: Infinity })).toThrow(TypeError);
            expect(() => cachedKeys(load, { key, timeout: 0 })).toThrow(TypeError);
            expect(() => cachedKeys(load, { key, timeout: 2_147_484 })).toThrow(TypeError);

            for (const max of [NaN, Infinity, 0, -1, 1.5]) {
                expect(() => cachedKeys(load, { key, max })).toThrow(TypeError);
            }
            expect(() => cachedKeys(load, { key, max: 1 })).not.toThrow();
        });
    });

    describe('jwks', () => {
        it('should resolve the right key from a JWKS endpoint', async () => {
            const a = await createSigningKey('a');
            const b = await createSigningKey('b');

            const urls : string[] = [];
            const context = await createContext(b, {
                fetch: async (input) => {
                    urls.push(String(input));
                    return Response.json({ keys: [a.jwk, b.jwk] });
                },
            });

            const key = await resolveVerificationKey(jwks('https://issuer.example/jwks'), context);
            const exported = await exportJWK(key);

            expect(exported.n).toEqual(b.jwk.n);
            expect(urls).toEqual(['https://issuer.example/jwks']);
        });

        it('should fail when the endpoint answers 500', async () => {
            const key = await createSigningKey('a');
            const context = await createContext(key, { fetch: async () => new Response('error', { status: 500 }) });

            await expectKeyUnavailable(resolveVerificationKey(jwks('https://issuer.example/jwks'), context));
        });
    });
});
