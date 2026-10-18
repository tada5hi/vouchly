import type { JWTPayload } from 'jose';

export type TokenCacheEntry = {
    claims: JWTPayload,
    /**
     * Issuer.id, or the issuer's index in the verifier's list when it has no id.
     */
    issuer: string,
    source: 'local' | 'introspection',
    /**
     * The token header's `typ`, for a locally verified token that carried one.
     */
    typ?: string,
    /**
     * The token header's `alg`, for a locally verified token.
     */
    alg?: string,
};

export interface ITokenCache {
    get(key: string): Promise<TokenCacheEntry | undefined>;

    /**
     * @param ttl seconds; a value <= 0 stores nothing.
     */
    set(key: string, entry: TokenCacheEntry, ttl: number): Promise<void>;
}

export type MemoryTokenCacheOptions = {
    /**
     * Maximum number of entries, default 10000.
     */
    max?: number,
};
