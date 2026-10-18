import type { JWTPayload } from 'jose';
import type { KeySource } from '../key';

export type IntrospectionAuthorizationContext = {
    /**
     * true when the previous attempt was answered with 401.
     */
    retry: boolean,
};

export type IntrospectionOptions = {
    /**
     * Default: the issuer's discovered introspection_endpoint.
     */
    endpoint?: string,
    /**
     * Client credentials (sent as HTTP Basic), or a function returning the
     * whole Authorization header value. After a 401 a function is called
     * again with `retry: true` and the request is repeated once.
     */
    authorization?: { clientId: string, clientSecret: string } | ((context: IntrospectionAuthorizationContext) => string | Promise<string>),
    /**
     * Upper bound, in seconds, for caching an introspection result.
     */
    maxCacheTTL?: number,
};

export type Issuer = {
    id?: string,
    /**
     * A string matches `iss` exactly. A function sees UNVERIFIED claims:
     * it only selects this config and never replaces verification.
     */
    issuer: string | ((claims: JWTPayload) => boolean),
    /**
     * Default: discovery() when issuer is a string.
     */
    keys?: KeySource,
    /**
     * Default: 'local'.
     */
    verification?: 'local' | 'remote',
    introspection?: IntrospectionOptions,
    audience?: string | string[],
    /**
     * Default: the resolved key's algorithm only. A JWK without `alg` is
     * imported with the token header's `alg`, restricted to what its key
     * type supports; set this to pin the algorithm.
     */
    algorithms?: string[],
    typ?: string,
    /**
     * Seconds, default 0.
     */
    clockTolerance?: number,
    /**
     * Default: ['exp'].
     */
    requiredClaims?: string[],
    claims?: (claims: JWTPayload) => boolean | Promise<boolean>,
};
