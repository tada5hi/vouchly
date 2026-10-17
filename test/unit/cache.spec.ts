import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    vi,
} from 'vitest';
import type { TokenCacheEntry } from '../../src';
import { MemoryTokenCache, hashToken } from '../../src';

function createEntry(sub: string) : TokenCacheEntry {
    return {
        claims: { sub },
        issuer: '0',
        source: 'local',
    };
}

describe('src/cache', () => {
    beforeEach(() => {
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    it('should return a stored entry until its ttl passes', async () => {
        const cache = new MemoryTokenCache();
        const entry = createEntry('a');

        await cache.set('a', entry, 10);
        expect(await cache.get('a')).toEqual(entry);

        vi.advanceTimersByTime(9_999);
        expect(await cache.get('a')).toEqual(entry);

        vi.advanceTimersByTime(1);
        expect(await cache.get('a')).toBeUndefined();
    });

    it('should evict the least recently used entry beyond max', async () => {
        const cache = new MemoryTokenCache({ max: 2 });

        await cache.set('a', createEntry('a'), 60);
        await cache.set('b', createEntry('b'), 60);

        // refresh recency of a, so b is the least recently used
        expect(await cache.get('a')).toBeDefined();

        await cache.set('c', createEntry('c'), 60);

        expect(await cache.get('a')).toBeDefined();
        expect(await cache.get('b')).toBeUndefined();
        expect(await cache.get('c')).toBeDefined();
    });

    it('should not exceed max when overwriting a key', async () => {
        const cache = new MemoryTokenCache({ max: 2 });

        await cache.set('a', createEntry('a'), 60);
        await cache.set('b', createEntry('b'), 60);
        await cache.set('a', createEntry('a2'), 60);

        expect(await cache.get('a')).toEqual(createEntry('a2'));
        expect(await cache.get('b')).toBeDefined();
    });

    it('should not let a caller mutate a stored entry', async () => {
        const cache = new MemoryTokenCache();
        const entry = createEntry('a');

        await cache.set('a', entry, 60);
        entry.claims.sub = 'changed';

        const read = await cache.get('a');
        read!.claims.sub = 'changed';

        expect((await cache.get('a'))!.claims.sub).toEqual('a');
    });

    it.each([0, -1])('should store nothing for ttl %s', async (ttl) => {
        const cache = new MemoryTokenCache();

        await cache.set('a', createEntry('a'), ttl);
        expect(await cache.get('a')).toBeUndefined();
    });

    it('should hash a token to hex sha-256', async () => {
        expect(await hashToken('a')).toEqual('ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb');
    });
});
