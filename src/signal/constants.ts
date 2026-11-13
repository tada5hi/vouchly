/**
 * Seconds a request may take unless configured otherwise.
 */
export const TIMEOUT_DEFAULT = 10;

/**
 * setTimeout clamps a delay above 2^31 - 1 ms to 1 ms.
 */
export const TIMEOUT_MAX = 2_147_483;
