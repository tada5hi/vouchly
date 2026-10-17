import type { JWTPayload } from 'jose';
import {
    afterEach,
    describe,
    expect,
    it,
    vi,
} from 'vitest';
import type { Issuer, VerifierOptions } from '../../src';
import {
    MemoryTokenCache,
    VouchrErrorCode,
    createVerifier,
    introspect,
    isVouchrError,
} from '../../src';

const ISSUER = 'https://issuer.example';
const ENDPOINT = `${ISSUER}/token/introspect`;
const THUMBPRINT = 'bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2';

// Shaped like a compact JWS, so the verifier selects the issuer by `iss`.
const JWT = [
    'eyJhbGciOiJSUzI1NiJ9',
    btoa(JSON.stringify({ iss: ISSUER, sub: 'user' })).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
    'c2lnbmF0dXJl',
].join('.');

type RecordedRequest = {
    url: string,
    method: string | undefined,
    headers: Headers,
    body: string,
};

type Stub = {
    fetch: typeof fetch,
    requests: RecordedRequest[],
};

function now() : number {
    return Math.floor(Date.now() / 1000);
}

function createStub(answer: (request: RecordedRequest) => Response | Promise<Response>) : Stub {
    const requests : RecordedRequest[] = [];

    return {
        requests,
        fetch: async (input, init) => {
            const request : RecordedRequest = {
                url: String(input),
                method: init?.method,
                headers: new Headers(init?.headers),
                body: typeof init?.body === 'string' ? init.body : String(init?.body ?? ''),
            };
            requests.push(request);

            return answer(request);
        },
    };
}

function activeResponse(claims: JWTPayload = {}) : () => Response {
    return () => Response.json({
        active: true,
        sub: 'user',
        iss: ISSUER,
        exp: now() + 3600,
        ...claims,
    });
}

function introspectionIssuer(options: Partial<Issuer> = {}) : Issuer {
    return {
        id: 'remote',
        issuer: ISSUER,
        verification: 'introspection',
        introspection: {
            endpoint: ENDPOINT,
            authorization: { clientId: 'client', clientSecret: 'secret' },
        },
        ...options,
    };
}

function verifier(stub: Stub, issuer: Issuer = introspectionIssuer(), options: Partial<VerifierOptions> = {}) {
    return createVerifier({
        issuers: [issuer],
        fetch: stub.fetch,
        ...options,
    });
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

describe('src/introspection', () => {
    afterEach(() => {
        vi.useRealTimers();
    });

    it('should introspect an active token with a Basic header', async () => {
        const stub = createStub(activeResponse());

        const result = await verifier(stub).verify(JWT);

        expect(result.source).toBe('introspection');
        expect(result.issuer.id).toBe('remote');
        expect(result.claims.sub).toBe('user');

        expect(stub.requests).toHaveLength(1);
        const [request] = stub.requests;
        expect(request!.url).toBe(ENDPOINT);
        expect(request!.method).toBe('POST');
        expect(request!.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
        expect(request!.headers.get('accept')).toBe('application/json');
        expect(request!.headers.get('authorization')).toBe(`Basic ${btoa('client:secret')}`);
        expect(request!.body).toBe(`token=${encodeURIComponent(JWT)}`);
    });

    it('should form-encode the client credentials (RFC 6749 2.3.1)', async () => {
        const stub = createStub(activeResponse());

        await introspect(JWT, introspectionIssuer({
            introspection: {
                endpoint: ENDPOINT,
                authorization: { clientId: 'my client', clientSecret: 'p@ss:wörd' },
            },
        }), stub.fetch);

        expect(stub.requests[0]!.headers.get('authorization'))
            .toBe(`Basic ${btoa('my+client:p%40ss%3Aw%C3%B6rd')}`);
    });

    it('should send a function authorization value verbatim', async () => {
        const stub = createStub(activeResponse());

        await verifier(stub, introspectionIssuer({
            introspection: {
                endpoint: ENDPOINT,
                authorization: async () => 'Bearer service-token',
            },
        })).verify(JWT);

        expect(stub.requests[0]!.headers.get('authorization')).toBe('Bearer service-token');
    });

    it('should send no authorization header when none is configured', async () => {
        const stub = createStub(activeResponse());

        await verifier(stub, introspectionIssuer({ introspection: { endpoint: ENDPOINT } })).verify(JWT);

        expect(stub.requests[0]!.headers.has('authorization')).toBe(false);
    });

    it('should refuse an inactive token', async () => {
        const stub = createStub(() => Response.json({ active: false }));

        await expectCode(verifier(stub).verify(JWT), VouchrErrorCode.TOKEN_INACTIVE);
    });

    it('should refuse a non-2xx answer without echoing its body', async () => {
        const stub = createStub(() => new Response('internal secret detail', { status: 500 }));

        const error = await expectCode(verifier(stub).verify(JWT), VouchrErrorCode.INTROSPECTION_FAILED);
        expect((error as Error).message).toContain('500');
        expect((error as Error).message).not.toContain('internal secret detail');
    });

    it('should refuse a non-JSON answer', async () => {
        const stub = createStub(() => new Response('<html>login</html>', {
            status: 200,
            headers: { 'content-type': 'text/html' },
        }));

        await expectCode(verifier(stub).verify(JWT), VouchrErrorCode.INTROSPECTION_FAILED);
    });

    it('should refuse a fetch failure', async () => {
        const stub = createStub(() => {
            throw new TypeError('fetch failed');
        });

        const error = await expectCode(verifier(stub).verify(JWT), VouchrErrorCode.INTROSPECTION_FAILED);
        expect((error as Error).cause).toBeInstanceOf(TypeError);
    });

    it('should refuse an authorization function that throws', async () => {
        const stub = createStub(activeResponse());

        await expectCode(verifier(stub, introspectionIssuer({
            introspection: {
                endpoint: ENDPOINT,
                authorization: () => {
                    throw new Error('no token');
                },
            },
        })).verify(JWT), VouchrErrorCode.INTROSPECTION_FAILED);
        expect(stub.requests).toHaveLength(0);
    });

    it('should use the discovered introspection endpoint', async () => {
        const stub = createStub((request) => {
            if (request.url === `${ISSUER}/.well-known/openid-configuration`) {
                return Response.json({
                    issuer: ISSUER,
                    jwks_uri: `${ISSUER}/jwks`,
                    introspection_endpoint: ENDPOINT,
                });
            }

            return activeResponse()();
        });

        const result = await verifier(stub, introspectionIssuer({ introspection: {} })).verify(JWT);

        expect(result.source).toBe('introspection');
        expect(stub.requests.map((request) => request.url)).toEqual([
            `${ISSUER}/.well-known/openid-configuration`,
            ENDPOINT,
        ]);
    });

    it('should introspect with metadata that names no jwks_uri', async () => {
        const stub = createStub((request) => {
            if (request.url === `${ISSUER}/.well-known/openid-configuration`) {
                return Response.json({ issuer: ISSUER, introspection_endpoint: ENDPOINT });
            }

            return activeResponse()();
        });

        const result = await verifier(stub, introspectionIssuer({ introspection: {} })).verify(JWT);

        expect(result.source).toBe('introspection');
        expect(stub.requests.map((request) => request.url)).toEqual([
            `${ISSUER}/.well-known/openid-configuration`,
            ENDPOINT,
        ]);
    });

    it('should fail without an endpoint, and never fetch for a function issuer', async () => {
        const discovered = createStub((request) => {
            if (request.url.endsWith('/.well-known/openid-configuration')) {
                return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` });
            }

            return activeResponse()();
        });

        await expectCode(
            verifier(discovered, introspectionIssuer({ introspection: {} })).verify(JWT),
            VouchrErrorCode.INTROSPECTION_FAILED,
        );
        expect(discovered.requests).toHaveLength(1);

        const unmatched = createStub(activeResponse());
        await expectCode(
            introspect(JWT, introspectionIssuer({ issuer: () => true, introspection: {} }), unmatched.fetch),
            VouchrErrorCode.INTROSPECTION_FAILED,
        );
        expect(unmatched.requests).toHaveLength(0);
    });

    it('should apply the audience and the claims predicate to the response', async () => {
        const stub = createStub(activeResponse({ aud: ['api'], scope: 'read' }));

        const passing = verifier(stub, introspectionIssuer({ audience: 'api' }), { cache: false });
        await expect(passing.verify(JWT)).resolves.toBeDefined();

        const wrongAudience = verifier(stub, introspectionIssuer({ audience: 'other' }), { cache: false });
        await expectCode(wrongAudience.verify(JWT), VouchrErrorCode.CLAIM_INVALID);

        const refused = verifier(stub, introspectionIssuer({ claims: (claims) => claims.scope === 'write' }), { cache: false });
        await expectCode(refused.verify(JWT), VouchrErrorCode.CLAIM_INVALID);
    });

    it('should cache no longer than maxCacheTTL', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });

        const stub = createStub(activeResponse());
        const instance = verifier(stub, introspectionIssuer({
            introspection: {
                endpoint: ENDPOINT,
                maxCacheTTL: 5,
            },
        }));

        await instance.verify(JWT);
        await instance.verify(JWT);
        expect(stub.requests).toHaveLength(1);

        vi.advanceTimersByTime(6000);

        await instance.verify(JWT);
        expect(stub.requests).toHaveLength(2);
    });

    it('should not cache past the response exp', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(1_800_000_000_500);

        const stub = createStub(activeResponse({ exp: 1_800_000_002 }));
        const instance = verifier(stub, introspectionIssuer({
            introspection: {
                endpoint: ENDPOINT,
                maxCacheTTL: 60,
            },
        }));

        await instance.verify(JWT);
        vi.setSystemTime(1_800_000_001_999);
        await instance.verify(JWT);
        expect(stub.requests).toHaveLength(1);

        vi.setSystemTime(1_800_000_002_000);
        await instance.verify(JWT);
        expect(stub.requests).toHaveLength(2);
    });

    it('should refuse an expired response served by a cache that rounds its ttl up', async () => {
        vi.useFakeTimers({ toFake: ['Date'] });
        vi.setSystemTime(1_800_000_000_500);

        const stub = createStub(activeResponse({ exp: 1_800_000_002 }));
        const memory = new MemoryTokenCache();
        const instance = verifier(stub, introspectionIssuer(), {
            cacheNamespace: 'api',
            cache: {
                get: (k) => memory.get(k),
                set: (k, entry, ttl) => memory.set(k, entry, Math.ceil(ttl)),
            },
        });

        await instance.verify(JWT);

        vi.setSystemTime(1_800_000_002_000);
        await expectCode(instance.verify(JWT), VouchrErrorCode.TOKEN_EXPIRED);
        expect(stub.requests).toHaveLength(1);
    });

    it('should introspect an opaque token with the opaque issuer', async () => {
        const stub = createStub(activeResponse());

        const result = await verifier(stub, introspectionIssuer(), { opaque: 'remote' }).verify('abc123');
        expect(result.source).toBe('introspection');
        expect(stub.requests[0]!.body).toBe('token=abc123');

        await expectCode(verifier(stub).verify('abc123'), VouchrErrorCode.TOKEN_MALFORMED);
        expect(stub.requests).toHaveLength(1);
    });

    it('should enforce the certificate binding of a response, on hits too', async () => {
        const stub = createStub(activeResponse({ cnf: { 'x5t#S256': THUMBPRINT } }));
        const instance = verifier(stub);

        await expectCode(instance.verify(JWT), VouchrErrorCode.BINDING_MISMATCH);

        const result = await instance.verify(JWT, { certificateThumbprint: THUMBPRINT });
        expect(result.claims.cnf).toEqual({ 'x5t#S256': THUMBPRINT });

        await expectCode(instance.verify(JWT, { certificateThumbprint: 'wrong' }), VouchrErrorCode.BINDING_MISMATCH);
        expect(stub.requests).toHaveLength(1);
    });

    it('should enforce the certificate binding the token itself carries', async () => {
        const bound = [
            'eyJhbGciOiJSUzI1NiJ9',
            btoa(JSON.stringify({
                iss: ISSUER, 
                sub: 'user', 
                cnf: { 'x5t#S256': THUMBPRINT }, 
            }))
                .replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'),
            'c2lnbmF0dXJl',
        ].join('.');

        const stub = createStub(activeResponse());
        const instance = verifier(stub);

        await expectCode(instance.verify(bound), VouchrErrorCode.BINDING_MISMATCH);
        await expectCode(instance.verify(bound), VouchrErrorCode.BINDING_MISMATCH);

        const result = await instance.verify(bound, { certificateThumbprint: THUMBPRINT });
        expect(result.claims.cnf).toBeUndefined();
        expect(stub.requests).toHaveLength(1);

        const conflicting = createStub(activeResponse({ cnf: { 'x5t#S256': 'other' } }));
        await expectCode(
            verifier(conflicting).verify(bound, { certificateThumbprint: THUMBPRINT }),
            VouchrErrorCode.BINDING_MISMATCH,
        );
    });

    it('should not let a mutated result change the cached entry', async () => {
        const stub = createStub(activeResponse({ scope: 'read' }));
        const instance = verifier(stub);

        const first = await instance.verify(JWT);
        first.claims.scope = 'admin';

        const second = await instance.verify(JWT);
        expect(second.claims.scope).toBe('read');
        expect(stub.requests).toHaveLength(1);
    });
});
