import { VouchlyError, VouchlyErrorCode } from '../error';
import { TIMEOUT_DEFAULT, TIMEOUT_MAX } from './constants';
import type { TimeoutSignal } from './types';

/**
 * A timeout in seconds: the default when absent, else a finite number above
 * 0 and at most TIMEOUT_MAX, or a TypeError naming the option.
 */
export function resolveTimeout(value: number | undefined, name: string) : number {
    if (typeof value === 'undefined') {
        return TIMEOUT_DEFAULT;
    }

    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > TIMEOUT_MAX) {
        throw new TypeError(`The ${name} must be a positive number of seconds, at most ${TIMEOUT_MAX}.`);
    }

    return value;
}

/**
 * A signal aborted with a TimeoutError after `timeout` seconds. clear()
 * stops the timer once the work it bounds is done.
 */
export function createTimeoutSignal(timeout: number) : TimeoutSignal {
    const controller = new AbortController();
    const timer = setTimeout(() => {
        controller.abort(new DOMException('The operation timed out.', 'TimeoutError'));
    }, timeout * 1000);

    return {
        signal: controller.signal,
        clear: () => clearTimeout(timer),
    };
}

export function createTimeoutError(message: string, cause: unknown) : VouchlyError {
    return new VouchlyError(VouchlyErrorCode.TIMEOUT, message, { cause });
}
