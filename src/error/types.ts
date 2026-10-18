export type VouchlyErrorOptions = {
    cause?: unknown,
    /**
     * The HTTP status of a failed upstream answer, e.g. an introspection endpoint's.
     */
    status?: number,
};
