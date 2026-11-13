import type { JWTPayload } from 'jose';
import type { ITokenCache } from '../cache';
import type { Issuer } from '../issuer';

export type VerifierOptions = {
    issuers: Issuer[],
    /**
     * Default: a MemoryTokenCache; false disables caching.
     */
    cache?: ITokenCache | false,
    /**
     * Names the group of verifiers sharing a cache passed in; required then.
     * Every verifier using one namespace must have the same issuer
     * configuration, since a cache hit skips the key lookup and the
     * signature check. Must not contain NUL. The cache key is the SHA-256 of
     * the namespace, a NUL character and the token.
     */
    cacheNamespace?: string,
    /**
     * Default: the global fetch.
     */
    fetch?: typeof fetch,
    /**
     * The Issuer.id that introspects tokens which are not compact JWTs.
     */
    opaque?: string,
    /**
     * Seconds each introspection or discovery request may take, default 10.
     * Must be a finite number above 0 and at most 2147483. The bound is per
     * request, so a verification that needs discovery, the introspection
     * request and a retry after a 401 can take up to three times as long.
     * It does not bound the JWKS request of the discovery key source, which
     * keeps jose's own timeoutDuration.
     */
    timeout?: number,
};

export type VerifyOptions = {
    /**
     * The presented client certificate's SHA-256 thumbprint (base64url), for
     * RFC 8705 bound tokens. A provider is only invoked for a bound token.
     */
    certificateThumbprint?: string | (() => string | undefined | Promise<string | undefined>),
    /**
     * Aborts this verification: it rejects with the signal's reason, cancels
     * its introspection request and stores no result. A key load or discovery
     * shared with other verifications is not cancelled, only no longer awaited.
     */
    signal?: AbortSignal,
};

export type VerifyResult = {
    claims: JWTPayload,
    issuer: Issuer,
    source: 'local' | 'remote',
};

export interface IVerifier {
    verify(token: string, options?: VerifyOptions): Promise<VerifyResult>;
}
