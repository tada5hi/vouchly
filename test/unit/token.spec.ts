import { SignJWT, generateKeyPair } from 'jose';
import {
    beforeAll,
    describe,
    expect,
    it,
} from 'vitest';
import {
    VouchlyErrorCode,
    isCompactToken,
    isVouchlyError,
    parseToken,
} from '../../src';

function encode(input: unknown) : string {
    const bytes = new TextEncoder().encode(JSON.stringify(input));
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function expectMalformed(input: string) {
    let caught: unknown;
    try {
        parseToken(input);
    } catch (e) {
        caught = e;
    }

    expect(isVouchlyError(caught)).toBe(true);
    expect((caught as { code: string }).code).toBe(VouchlyErrorCode.TOKEN_MALFORMED);
}

describe('src/token', () => {
    let token: string;

    beforeAll(async () => {
        const { privateKey } = await generateKeyPair('ES256');
        token = await new SignJWT({ sub: 'alice' })
            .setProtectedHeader({ alg: 'ES256', kid: 'k1' })
            .setExpirationTime('5m')
            .sign(privateKey);
    });

    it('should parse a signed token', () => {
        const parsed = parseToken(token);
        expect(parsed.raw).toBe(token);
        expect(parsed.header.alg).toBe('ES256');
        expect(parsed.header.kid).toBe('k1');
        expect(parsed.claims.sub).toBe('alice');
        expect(isCompactToken(token)).toBe(true);
    });

    it.each([
        ['abc'],
        ['a.b'],
        ['a.b.c.d.e'],
        ['!!!.e30.sig'],
    ])('should reject %s', (input) => {
        expect(isCompactToken(input)).toBe(false);
        expectMalformed(input);
    });

    it.each([
        ['padding', (t: string) => `${t}==`],
        ['a space', (t: string) => `${t.slice(0, 10)} ${t.slice(10)}`],
        ['a tab', (t: string) => `${t}\t`],
        ['a leading space', (t: string) => ` ${t}`],
    ])('should reject a token altered by %s', (_label, alter) => {
        const altered = alter(token);
        expect(isCompactToken(altered)).toBe(false);
        expectMalformed(altered);
    });

    it.each([
        ['null', null],
        ['an array', ['a']],
        ['a string', 'claims'],
    ])('should reject a payload decoding to %s', (_label, payload) => {
        expectMalformed(`${encode({ alg: 'ES256' })}.${encode(payload)}.c2ln`);
    });

    it('should reject a header that is not an object', () => {
        expectMalformed(`${encode(['ES256'])}.${encode({ sub: 'a' })}.c2ln`);
    });

    it('should reject a segment that is not base64url JSON', () => {
        expectMalformed(`${encode({ alg: 'ES256' })}.bm90LWpzb24.c2ln`);
    });

    it('should decode a non-ASCII payload', () => {
        const parsed = parseToken(`${encode({ alg: 'ES256' })}.${encode({ name: 'Пётр' })}.c2ln`);
        expect(parsed.claims.name).toBe('Пётр');
    });
});
