import type { ITokenCache, MemoryTokenCacheOptions, TokenCacheEntry } from './types';

type MemoryTokenCacheItem = {
    entry: TokenCacheEntry,
    expiresAt: number,
};

export class MemoryTokenCache implements ITokenCache {
    protected max: number;

    // Map iteration follows insertion order, so the first key is the least recently used.
    protected items: Map<string, MemoryTokenCacheItem>;

    constructor(options: MemoryTokenCacheOptions = {}) {
        const max = options.max ?? 10_000;
        if (!Number.isSafeInteger(max) || max < 1) {
            throw new TypeError('The token cache max must be an integer of at least 1.');
        }

        this.max = max;
        this.items = new Map();
    }

    async get(key: string): Promise<TokenCacheEntry | undefined> {
        const item = this.items.get(key);
        if (!item) {
            return undefined;
        }

        this.items.delete(key);

        if (item.expiresAt <= Date.now()) {
            return undefined;
        }

        this.items.set(key, item);

        return structuredClone(item.entry);
    }

    async set(key: string, entry: TokenCacheEntry, ttl: number): Promise<void> {
        this.items.delete(key);

        if (!(ttl > 0)) {
            return;
        }

        this.items.set(key, {
            entry: structuredClone(entry),
            expiresAt: Date.now() + (ttl * 1000),
        });

        while (this.items.size > this.max) {
            const oldest = this.items.keys().next();
            if (oldest.done) {
                break;
            }

            this.items.delete(oldest.value);
        }
    }
}
