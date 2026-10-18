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
};

export type VerifyOptions = {
    /**
     * The presented client certificate's SHA-256 thumbprint (base64url), for
     * RFC 8705 bound tokens. A provider is only invoked for a bound token.
     */
    certificateThumbprint?: string | (() => string | undefined | Promise<string | undefined>),
};

export type VerifyResult = {
    claims: JWTPayload,
    issuer: Issuer,
    source: 'local' | 'introspection',
};

export interface IVerifier {
    verify(token: string, options?: VerifyOptions): Promise<VerifyResult>;
}
