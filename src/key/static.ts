import type { JWK } from 'jose';
import { createLocalJWKSet } from 'jose';
import type { KeySource } from './types';

export function staticKeys(keys: JWK[]) : KeySource {
    const set = createLocalJWKSet({ keys: structuredClone(keys) });

    return async (context) => set(context.token.header);
}
