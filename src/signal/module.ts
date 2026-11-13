import { VouchlyError, VouchlyErrorCode } from '../error';
import { TIMEOUT_DEFAULT, TIMEOUT_MAX } from './constants';
import type { DeadlineSignal, TimeoutSignal } from './types';

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
 * A signal aborted with a TimeoutError at `deadline` (a Date.now()
 * timestamp), which extend() can only move later.
 */
export function createDeadlineSignal(deadline: number) : DeadlineSignal {
    const controller = new AbortController();
    let at = deadline;
    let timer : ReturnType<typeof setTimeout> | undefined;

    const schedule = () => {
        clearTimeout(timer);
        timer = setTimeout(() => {
            controller.abort(new DOMException('The operation timed out.', 'TimeoutError'));
        }, Math.max(0, at - Date.now()));
    };

    schedule();

    return {
        signal: controller.signal,
        clear: () => clearTimeout(timer),
        extend: (value) => {
            if (!(value > at) || controller.signal.aborted) {
                return;
            }

            at = value;
            schedule();
        },
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

/**
 * Waits for shared work for at most `timeout` seconds of this caller's own,
 * and no longer than its signal: either rejects the wait (TIMEOUT, or the
 * signal's reason), never the work.
 */
export async function waitWithin<T>(
    promise: Promise<T>,
    timeout: number,
    message: string,
    signal?: AbortSignal,
) : Promise<T> {
    const timer = createTimeoutSignal(timeout);

    try {
        return await abortable(promise, combineSignals(timer.signal, signal));
    } catch (e) {
        if (signal?.aborted) {
            throw signal.reason;
        }

        if (timer.signal.aborted && e === timer.signal.reason) {
            throw createTimeoutError(message, e);
        }

        throw e;
    } finally {
        timer.clear();
    }
}
