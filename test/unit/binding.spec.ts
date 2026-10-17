import type { JWK } from 'jose';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import {
    describe,
    expect,
    it,
} from 'vitest';
import type { Verifier } from '../../src';
import {
    VouchrErrorCode,
    assertCertificateBinding,
    createVerifier,
    isVouchrError,
    staticKeys,
} from '../../src';

const ISSUER = 'https://issuer.example';
const THUMBPRINT = 'bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2';

async function setup() : Promise<{ verifier: Verifier, sign: (claims?: Record<string, unknown>) => Promise<string> }> {
    const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
    const jwk : JWK = {
        ...(await exportJWK(publicKey)),
        kid: 'k1',
        alg: 'ES256',
        use: 'sig',
    };

    return {
        verifier: createVerifier({ issuers: [{ issuer: ISSUER, keys: staticKeys([jwk]) }] }),
        sign: (claims = {}) => new SignJWT({
            sub: 'client', 
            iss: ISSUER, 
            ...claims, 
        })
            .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
            .setExpirationTime('1h')
            .sign(privateKey),
    };
}

async function expectMismatch(promise: Promise<unknown>) {
    let error : unknown;
    try {
        await promise;
    } catch (e) {
        error = e;
    }

    expect(isVouchrError(error)).toBe(true);
    expect((error as { code: VouchrErrorCode }).code).toBe(VouchrErrorCode.BINDING_MISMATCH);
}

describe('src/verifier binding', () => {
    it('should check claims directly', () => {
        expect(() => assertCertificateBinding({ sub: 'x' }, undefined)).not.toThrow();
        expect(() => assertCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, THUMBPRINT)).not.toThrow();
        expect(() => assertCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, undefined)).toThrow();
        expect(() => assertCertificateBinding({ cnf: { 'x5t#S256': THUMBPRINT } }, 'other')).toThrow();
        expect(() => assertCertificateBinding({ cnf: { 'x5t#S256': '' } }, '')).toThrow();
        expect(() => assertCertificateBinding({ cnf: { jkt: 'abc' } }, THUMBPRINT)).toThrow();
        expect(() => assertCertificateBinding({ cnf: 'x' }, THUMBPRINT)).toThrow();
    });

    it('should refuse a bound token without or with a wrong thumbprint', async () => {
        const { verifier, sign } = await setup();
        const token = await sign({ cnf: { 'x5t#S256': THUMBPRINT } });

        await expectMismatch(verifier.verify(token));
        await expectMismatch(verifier.verify(token, { certificateThumbprint: 'wrong' }));
        await expectMismatch(verifier.verify(token, { certificateThumbprint: async () => undefined }));
    });

    it('should accept a matching value and an async provider', async () => {
        const { verifier, sign } = await setup();
        const token = await sign({ cnf: { 'x5t#S256': THUMBPRINT } });

        const first = await verifier.verify(token, { certificateThumbprint: THUMBPRINT });
        expect(first.claims.sub).toBe('client');

        const second = await verifier.verify(token, { certificateThumbprint: async () => THUMBPRINT });
        expect(second.claims.sub).toBe('client');
    });

    it('should not invoke the provider for an unbound token', async () => {
        const { verifier, sign } = await setup();
        let calls = 0;

        await verifier.verify(await sign(), {
            certificateThumbprint: () => {
                calls++;
                return THUMBPRINT;
            },
        });

        expect(calls).toBe(0);
    });

    it('should enforce the binding on a cache hit', async () => {
        const { verifier, sign } = await setup();
        const token = await sign({ cnf: { 'x5t#S256': THUMBPRINT } });

        await verifier.verify(token, { certificateThumbprint: THUMBPRINT });
        await expectMismatch(verifier.verify(token));
    });

    it('should not let a mutated result change the next one', async () => {
        const { verifier, sign } = await setup();
        const token = await sign({ cnf: { 'x5t#S256': THUMBPRINT } });

        const first = await verifier.verify(token, { certificateThumbprint: THUMBPRINT });
        (first.claims.cnf as Record<string, unknown>)['x5t#S256'] = 'evil';
        delete first.claims.cnf;

        await expectMismatch(verifier.verify(token));

        const second = await verifier.verify(token, { certificateThumbprint: THUMBPRINT });
        expect(second.claims.cnf).toEqual({ 'x5t#S256': THUMBPRINT });

        (second.claims.cnf as Record<string, unknown>)['x5t#S256'] = 'evil';
        const third = await verifier.verify(token, { certificateThumbprint: THUMBPRINT });
        expect(third.claims.cnf).toEqual({ 'x5t#S256': THUMBPRINT });
    });
});
