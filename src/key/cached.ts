import type { JWK } from 'jose';
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
    const max = Math.max(1, options.max ?? 100);

    if (!Number.isFinite(ttl) || ttl < 0) {
        throw new TypeError('The key cache ttl must be a finite, non-negative number of seconds.');
    }

    // setTimeout clamps a delay above 2^31 - 1 ms to 1 ms
    if (!Number.isFinite(timeout) || timeout <= 0 || timeout * 1000 > 2_147_483_647) {
        throw new TypeError('The key cache timeout must be a positive number of seconds, at most 2147483.');
    }

    // Map iteration follows insertion order, so the first key is the oldest.
    const items = new Map<string, CachedKeysItem>();
    const flights = new Map<string, Promise<JWK>>();

    return async (context) => {
        const key = options.key(context);

        const item = items.get(key);
        if (item) {
            if (item.expiresAt > Date.now()) {
                return structuredClone(item.jwk);
            }

            items.delete(key);
        }

        const pending = flights.get(key);
        if (pending) {
            return structuredClone(await pending);
        }

        let timer: ReturnType<typeof setTimeout> | undefined;
        const deadline = new Promise<never>((_resolve, reject) => {
            timer = setTimeout(() => {
                reject(new Error('Loading the key timed out.'));
            }, timeout * 1000);
        });

        // A stalled load must not pin every later lookup of the key: the
        // flight settles at the deadline, and a load finishing after it is
        // dropped instead of stored.
        const flight : Promise<JWK> = Promise.race([
            Promise.resolve().then(() => load(context)),
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
                clearTimeout(timer);
                if (flights.get(key) === flight) {
                    flights.delete(key);
                }
            });

        flights.set(key, flight);

        return structuredClone(await flight);
    };
}
