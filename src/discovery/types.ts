export type ProviderMetadata = {
    issuer: string,
    /**
     * Required by the discovery key source, not by introspection.
     */
    jwks_uri?: string,
    introspection_endpoint?: string,
};

export type DiscoveryOptions = {
    /**
     * Seconds the provider metadata of an issuer is reused, default 600.
     */
    cacheMaxAge?: number,
};
