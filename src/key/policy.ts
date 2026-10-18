import type { CryptoKey, JWK } from 'jose';

const RSA_MIN_MODULUS_LENGTH = 2048;

/**
 * Throws an Error when a JWK must never be used to verify a signature.
 */
export function assertJWKPolicy(jwk: JWK) : void {
    if (jwk.kty === 'oct') {
        throw new Error('A symmetric key (kty "oct") is not accepted.');
    }

    if (typeof jwk.use !== 'undefined' && jwk.use !== 'sig') {
        throw new Error(`A key with use "${jwk.use}" is not a signature key.`);
    }
}

/**
 * Throws an Error when a CryptoKey must never be used to verify a signature.
 */
export function assertCryptoKeyPolicy(key: CryptoKey) : void {
    if (key.type === 'secret') {
        throw new Error('A symmetric key is not accepted.');
    }

    const { modulusLength } = key.algorithm as { modulusLength?: unknown };
    if (typeof modulusLength === 'number' && modulusLength < RSA_MIN_MODULUS_LENGTH) {
        throw new Error(`An RSA key of ${modulusLength} bits is too small, at least ${RSA_MIN_MODULUS_LENGTH} are required.`);
    }
}
