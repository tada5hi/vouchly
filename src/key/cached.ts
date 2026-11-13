import type { JWK } from 'jose';
import { abortable, createTimeoutError, createTimeoutSignal } from '../signal';
import type { CachedKeysOptions, KeySource, KeySourceContext } from './types';

type CachedKeysItem = {
    jwk: JWK,
    expiresAt: number,
};

export function cachedKeys(
    load: (context: KeySourceContext) => Promise<JWK>,
    options: CachedKeysOptions,
) : KeySource {
    const ttl = options.ttl ?? 300;
    const timeout = options.timeout ?? 10;
    const max = options.max ?? 100;

    if (!Number.isFinite(ttl) || ttl < 0) {
        throw new TypeError('The key cache ttl must be a finite, non-negative number of seconds.');
    }

    if (!Number.isSafeInteger(max) || max < 1) {
        throw new TypeError('The key cache max must be an integer of at least 1.');
    }

    // setTimeout clamps a delay above 2^31 - 1 ms to 1 ms
    if (!Number.isFinite(timeout) || timeout <= 0 || timeout * 1000 > 2_147_483_647) {
        throw new TypeError('The key cache timeout must be a positive number of seconds, at most 2147483.');
    }

    // Map iteration follows insertion order, so the first key is the oldest.
    const items = new Map<string, CachedKeysItem>();
    const flights = new Map<string, Promise<JWK>>();

    return async (context) => {
        context.signal?.throwIfAborted();

        const key = options.key(context);

        const item = items.get(key);

        if (item) {
            if (item.expiresAt > Date.now()) {
                return structuredClone(item.jwk);
            }

            items.delete(key);
        }

        const pending = flights.get(key);

        // The flight is shared, so a caller's signal only stops its own wait.
        if (pending) {
            return structuredClone(await abortable(pending, context.signal));
        }

        const timer = createTimeoutSignal(timeout);
        const deadline = new Promise<never>((_resolve, reject) => {
            timer.signal.addEventListener('abort', () => {
                reject(createTimeoutError('Loading the key timed out.', timer.signal.reason));
            }, { once: true });
        });

        // A stalled load must not pin every later lookup of the key: the
        // flight settles at the deadline, the load's signal aborts, and a
        // load finishing after it is dropped instead of stored.
        const flight : Promise<JWK> = Promise.race([
            Promise.resolve().then(() => load({ ...context, signal: timer.signal })),
            deadline,
        ])
            .then((jwk) => {
                if (ttl > 0) {
                    items.delete(key);
                    items.set(key, {
                        jwk: structuredClone(jwk),
                        expiresAt: Date.now() + (ttl * 1000),
                    });

                    while (items.size > max) {
                        const oldest = items.keys().next();

                        if (oldest.done) {
                            break;
                        }

                        items.delete(oldest.value);
                    }
                }

                return jwk;
            })
            .finally(() => {
                timer.clear();

                if (flights.get(key) === flight) {
                    flights.delete(key);
                }
            });

        flights.set(key, flight);

        return structuredClone(await abortable(flight, context.signal));
    };
}
