import type { JWK } from 'jose';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import {
    afterEach,
    describe,
    expect,
    it,
    vi,
} from 'vitest';
import type { Issuer, KeySourceContext } from '../../src';
import {
    VouchlyErrorCode,
    createVerifier,
    discovery,
    fetchProviderMetadata,
    isVouchlyError,
    parseToken,
    resolveVerificationKey,
} from '../../src';

const ISSUER = 'https://issuer.example/realms/master';

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

type Provider = {
    fetch: typeof fetch,
    urls: string[],
};

function createProvider(key: SigningKey, metadata: Record<string, unknown> = {}) : Provider {
    const urls : string[] = [];

    return {
        urls,
        fetch: async (input) => {
            const url = String(input);
            urls.push(url);

            if (url === `${ISSUER}/.well-known/openid-configuration`) {
                return Response.json({
                    issuer: ISSUER,
                    jwks_uri: `${ISSUER}/jwks`,
                    ...metadata,
                });
            }

            if (url === `${ISSUER}/jwks`) {
                return Response.json({ keys: [key.jwk] });
            }

            return new Response('not found', { status: 404 });
        },
    };
}

async function createContext(
    key: SigningKey,
    fetchFn: typeof fetch,
    issuer: Issuer['issuer'] = ISSUER,
) : Promise<KeySourceContext> {
    const token = await new SignJWT({ sub: 'user' })
        .setProtectedHeader({ alg: 'RS256', kid: key.jwk.kid })
        .setIssuer(ISSUER)
        .setExpirationTime('1h')
        .sign(key.privateKey);

    return {
        token: parseToken(token),
        issuer: { issuer },
        fetch: fetchFn,
    };
}

async function expectKeyUnavailable(promise: Promise<unknown>) {
    let error : unknown;
    try {
        await promise;
    } catch (e) {
        error = e;
    }

    expect(isVouchlyError(error)).toBe(true);
    expect((error as { code: string }).code).toEqual(VouchlyErrorCode.KEY_UNAVAILABLE);
}

describe('src/discovery', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        vi.useRealTimers();
    });

    it('should fetch the metadata, then the jwks_uri, and resolve the key', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key);
        const context = await createContext(key, provider.fetch);

        const resolved = await resolveVerificationKey(discovery(), context);
        const exported = await exportJWK(resolved);

        expect(exported.n).toEqual(key.jwk.n);
        expect(provider.urls).toEqual([
            `${ISSUER}/.well-known/openid-configuration`,
            `${ISSUER}/jwks`,
        ]);
    });

    it('should strip one trailing slash of the issuer', async () => {
        const urls : string[] = [];

        const metadata = await fetchProviderMetadata(`${ISSUER}/`, async (input) => {
            urls.push(String(input));
            return Response.json({ issuer: `${ISSUER}/`, jwks_uri: `${ISSUER}/jwks` });
        });

        expect(metadata.jwks_uri).toEqual(`${ISSUER}/jwks`);
        expect(urls).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
    });

    it('should return the introspection endpoint when the provider names one', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key, { introspection_endpoint: `${ISSUER}/token/introspect` });

        const metadata = await fetchProviderMetadata(ISSUER, provider.fetch);

        expect(metadata).toEqual({
            issuer: ISSUER,
            jwks_uri: `${ISSUER}/jwks`,
            introspection_endpoint: `${ISSUER}/token/introspect`,
        });
    });

    it('should refuse metadata whose issuer differs from the configured one', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key, { issuer: 'https://evil.example' });
        const context = await createContext(key, provider.fetch);

        await expectKeyUnavailable(resolveVerificationKey(discovery(), context));
        expect(provider.urls).toEqual([`${ISSUER}/.well-known/openid-configuration`]);
    });

    it('should refuse metadata without a jwks_uri', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key, { jwks_uri: undefined });
        const context = await createContext(key, provider.fetch);

        await expectKeyUnavailable(resolveVerificationKey(discovery(), context));
    });

    it('should refuse a function issuer without fetching anything', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key);
        const context = await createContext(key, provider.fetch, () => true);

        await expectKeyUnavailable(resolveVerificationKey(discovery(), context));
        expect(provider.urls).toEqual([]);
    });

    it('should fetch the metadata once for two verifications', async () => {
        const key = await createSigningKey('a');
        const provider = createProvider(key);
        const source = discovery();

        await resolveVerificationKey(source, await createContext(key, provider.fetch));
        await resolveVerificationKey(source, await createContext(key, provider.fetch));

        const metadataRequests = provider.urls
            .filter((url) => url.endsWith('/.well-known/openid-configuration'));

        expect(metadataRequests).toHaveLength(1);
    });

    it('should fail fast for 30 seconds after a failure, then try again', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });

        const key = await createSigningKey('a');
        const provider = createProvider(key);

        let calls = 0;
        const flaky : typeof fetch = async (input, init) => {
            calls++;
            if (calls === 1) {
                return new Response('error', { status: 500 });
            }

            return provider.fetch(input, init);
        };

        await expectKeyUnavailable(resolveVerificationKey(discovery(), await createContext(key, flaky)));
        expect(calls).toBe(1);

        vi.advanceTimersByTime(29_999);
        await expectKeyUnavailable(resolveVerificationKey(discovery(), await createContext(key, flaky)));
        expect(calls).toBe(1);

        vi.advanceTimersByTime(1);
        const resolved = await resolveVerificationKey(discovery(), await createContext(key, flaky));
        expect((await exportJWK(resolved)).n).toEqual(key.jwk.n);
    });

    it('should share one discovery instance between verifiers using the default fetch', async () => {
        const issuer = 'https://shared.example';
        const key = await createSigningKey('a');
        const urls : string[] = [];

        vi.stubGlobal('fetch', async (input: string | URL | Request) => {
            const url = String(input);
            urls.push(url);

            if (url === `${issuer}/.well-known/openid-configuration`) {
                return Response.json({ issuer, jwks_uri: `${issuer}/jwks` });
            }

            return Response.json({ keys: [key.jwk] });
        });

        const keys = discovery();
        const first = createVerifier({ issuers: [{ issuer, keys }], cache: false });
        const second = createVerifier({ issuers: [{ issuer, keys }], cache: false });

        const token = await new SignJWT({ sub: 'user' })
            .setProtectedHeader({ alg: 'RS256', kid: key.jwk.kid })
            .setIssuer(issuer)
            .setExpirationTime('1h')
            .sign(key.privateKey);

        await first.verify(token);
        await second.verify(token);

        expect(urls).toEqual([
            `${issuer}/.well-known/openid-configuration`,
            `${issuer}/jwks`,
        ]);
    });
});
