import type { CryptoKey, JWK } from 'jose';
import { importJWK } from 'jose';
import { VouchrError, VouchrErrorCode, isVouchrError } from '../error';
import { assertCryptoKeyPolicy, assertJWKPolicy } from './policy';
import type { KeySource, KeySourceContext } from './types';

function isJWK(input: CryptoKey | JWK) : input is JWK {
    return typeof (input as JWK).kty === 'string';
}

async function resolve(source: KeySource, context: KeySourceContext) : Promise<CryptoKey> {
    const output = await source(context);

    let key : CryptoKey | Uint8Array;
    if (isJWK(output)) {
        assertJWKPolicy(output);
        key = await importJWK(output, output.alg ?? context.token.header.alg);
    } else {
        key = output;
    }

    if (key instanceof Uint8Array) {
        throw new Error('A symmetric key is not accepted.');
    }

    assertCryptoKeyPolicy(key);

    return key;
}

/**
 * Resolves the key a token is verified with. Every failure, including a key
 * the policy refuses, is a KEY_UNAVAILABLE VouchrError.
 */
export async function resolveVerificationKey(source: KeySource, context: KeySourceContext) : Promise<CryptoKey> {
    try {
        return await resolve(source, context);
    } catch (e) {
        if (isVouchrError(e) && e.code === VouchrErrorCode.KEY_UNAVAILABLE) {
            throw e;
        }

        const message = e instanceof Error && e.message ?
            `The verification key is unavailable: ${e.message}` :
            'The verification key is unavailable.';

        throw new VouchrError(VouchrErrorCode.KEY_UNAVAILABLE, message, { cause: e });
    }
}
