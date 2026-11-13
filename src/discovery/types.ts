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
     * Seconds this call waits for the metadata request, default 10. Calls
     * sharing one request each wait for their own timeout; the request runs
     * until the latest of their deadlines.
     */
    timeout?: number,
    /**
     * Stops this call waiting: it rejects with the signal's reason, while the
     * shared request goes on for the other callers.
     */
    signal?: AbortSignal,
};
