import type { RemoteJWKSet } from 'jose';
import { createRemoteJWKSet, customFetch } from 'jose';
import type { JWKSOptions, KeySource } from './types';

export function jwks(url: string | URL, options: JWKSOptions = {}) : KeySource {
    const target = new URL(url);

    // One set (and so one jose key cache) per fetch implementation.
    const sets = new WeakMap<typeof fetch, RemoteJWKSet>();

    return async (context) => {
        let set = sets.get(context.fetch);
        if (!set) {
            set = createRemoteJWKSet(target, {
                cacheMaxAge: options.cacheMaxAge,
                cooldownDuration: options.cooldownDuration,
                timeoutDuration: options.timeoutDuration,
                [customFetch]: context.fetch,
            });
            sets.set(context.fetch, set);
        }

        return set(context.token.header);
    };
}
