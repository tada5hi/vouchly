import type { VouchlyErrorCode } from './constants';
import { VOUCHLY_ERROR_MARKER } from './constants';
import type { VouchlyErrorOptions } from './types';

export class VouchlyError extends Error {
    readonly code: VouchlyErrorCode;

    readonly [VOUCHLY_ERROR_MARKER] = true;

    constructor(code: VouchlyErrorCode, message?: string, options?: VouchlyErrorOptions) {
        super(message || code, options);

        this.name = 'VouchlyError';
        this.code = code;
    }
}

export function isVouchlyError(input: unknown): input is VouchlyError {
    if (typeof input !== 'object' || input === null) {
        return false;
    }

    return (input as Record<symbol, unknown>)[VOUCHLY_ERROR_MARKER] === true;
}
