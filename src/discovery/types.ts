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

export type FetchProviderMetadataOptions = DiscoveryOptions & {
    /**
     * Seconds the metadata request may take, default 10. It bounds the one
     * request shared by concurrent calls, so the call starting it decides.
     */
    timeout?: number,
};
