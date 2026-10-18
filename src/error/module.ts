import type { VouchrErrorCode } from './constants';
import { VOUCHR_ERROR_MARKER } from './constants';
import type { VouchrErrorOptions } from './types';

export class VouchrError extends Error {
    readonly code: VouchrErrorCode;

    readonly [VOUCHR_ERROR_MARKER] = true;

    constructor(code: VouchrErrorCode, message?: string, options?: VouchrErrorOptions) {
        super(message || code, options);

        this.name = 'VouchrError';
        this.code = code;
    }
}

export function isVouchrError(input: unknown): input is VouchrError {
    if (typeof input !== 'object' || input === null) {
        return false;
    }

    return (input as Record<symbol, unknown>)[VOUCHR_ERROR_MARKER] === true;
}
