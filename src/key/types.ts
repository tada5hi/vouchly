import type { CryptoKey, JWK } from 'jose';
import type { Issuer } from '../issuer';
import type { ParsedToken } from '../token';

export type KeySourceContext = {
    token: ParsedToken,
    issuer: Issuer,
    fetch: typeof fetch,
};

export type KeySource = (context: KeySourceContext) => Promise<CryptoKey | JWK>;

export type JWKSOptions = {
    /**
     * Milliseconds, see jose createRemoteJWKSet.
     */
    cacheMaxAge?: number,
    /**
     * Milliseconds, see jose createRemoteJWKSet.
     */
    cooldownDuration?: number,
    /**
     * Milliseconds, see jose createRemoteJWKSet.
     */
    timeoutDuration?: number,
};

export type CachedKeysOptions = {
    /**
     * The cache key of the context; one load is shared per key.
     */
    key: (context: KeySourceContext) => string,
    /**
     * Seconds, default 300; 0 caches nothing.
     */
    ttl?: number,
    /**
     * Seconds, default 10, at most 2147483.
     */
    timeout?: number,
    /**
     * Maximum number of entries, default 100.
     */
    max?: number,
};
