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

/**
 * The signal a request is sent with: the timeout, and the caller's signal
 * when there is one.
 */
export function combineSignals(timeout: AbortSignal, signal?: AbortSignal) : AbortSignal {
    return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

export function createTimeoutError(message: string, cause: unknown) : VouchlyError {
    return new VouchlyError(VouchlyErrorCode.TIMEOUT, message, { cause });
}

/**
 * Waits for work the caller does not own: an abort rejects the wait with the
 * signal's reason, the work itself goes on.
 */
export function abortable<T>(promise: Promise<T>, signal?: AbortSignal) : Promise<T> {
    if (!signal) {
        return promise;
    }

    return new Promise<T>((resolve, reject) => {
        if (signal.aborted) {
            promise.catch(() => undefined);
            reject(signal.reason);

            return;
        }

        const onAbort = () => {
            reject(signal.reason);
        };

        signal.addEventListener('abort', onAbort, { once: true });

        promise.then((value) => {
            signal.removeEventListener('abort', onAbort);
            resolve(value);
        }, (e: unknown) => {
            signal.removeEventListener('abort', onAbort);
            reject(e);
        });
    });
}
