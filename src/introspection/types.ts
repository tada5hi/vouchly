export type IntrospectionResponse = {
    active: boolean,
    [key: string]: unknown,
};

export type IntrospectOptions = {
    /**
     * Seconds each request may take, default 10: the discovery of the
     * endpoint, the introspection request and its retry after a 401.
     */
    timeout?: number,
};
