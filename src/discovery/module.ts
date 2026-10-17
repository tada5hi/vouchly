import type { DiscoveryOptions, ProviderMetadata } from './types';

const CACHE_MAX_AGE = 600;
const TIMEOUT = 10_000;

type MetadataItem = {
    metadata: ProviderMetadata,
    fetchedAt: number,
};

// Keyed by fetch implementation, then by the configured issuer string, so
// two verifiers with different fetch functions never share an answer.
const items = new WeakMap<typeof fetch, Map<string, MetadataItem>>();
const flights = new WeakMap<typeof fetch, Map<string, Promise<ProviderMetadata>>>();

function scope<T>(store: WeakMap<typeof fetch, Map<string, T>>, fetchFn: typeof globalThis.fetch) : Map<string, T> {
    let map = store.get(fetchFn);
    if (!map) {
        map = new Map();
        store.set(fetchFn, map);
    }

    return map;
}

function isRecord(input: unknown) : input is Record<string, unknown> {
    return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function isURL(input: unknown) : input is string {
    return typeof input === 'string' && URL.canParse(input);
}

async function load(issuer: string, fetchFn: typeof globalThis.fetch) : Promise<ProviderMetadata> {
    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;

    const response = await fetchFn(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(TIMEOUT),
    });

    if (!response.ok) {
        throw new Error(`The provider metadata request answered ${response.status}.`);
    }

    const body : unknown = await response.json();
    if (!isRecord(body)) {
        throw new Error('The provider metadata is not a JSON object.');
    }

    // OIDC Discovery 1.0, section 4.3.
    if (body.issuer !== issuer) {
        throw new Error('The provider metadata names another issuer.');
    }

    if (!isURL(body.jwks_uri)) {
        throw new Error('The provider metadata has no valid jwks_uri.');
    }

    const metadata : ProviderMetadata = {
        issuer: body.issuer,
        jwks_uri: body.jwks_uri,
    };

    if (typeof body.introspection_endpoint !== 'undefined') {
        if (!isURL(body.introspection_endpoint)) {
            throw new Error('The provider metadata has an invalid introspection_endpoint.');
        }

        metadata.introspection_endpoint = body.introspection_endpoint;
    }

    return metadata;
}

/**
 * Reads `<issuer>/.well-known/openid-configuration`. The issuer must come
 * from configuration, never from a token. Answers are reused for
 * cacheMaxAge seconds; failures are not.
 */
export async function fetchProviderMetadata(
    issuer: string,
    fetchFn: typeof globalThis.fetch,
    options: DiscoveryOptions = {},
) : Promise<ProviderMetadata> {
    const cacheMaxAge = options.cacheMaxAge ?? CACHE_MAX_AGE;

    const cached = scope(items, fetchFn);
    const item = cached.get(issuer);
    if (item && Date.now() - item.fetchedAt < cacheMaxAge * 1000) {
        return structuredClone(item.metadata);
    }

    const pending = scope(flights, fetchFn);
    let flight = pending.get(issuer);
    if (!flight) {
        flight = load(issuer, fetchFn)
            .then((metadata) => {
                cached.set(issuer, { metadata, fetchedAt: Date.now() });
                return metadata;
            })
            .finally(() => {
                pending.delete(issuer);
            });

        pending.set(issuer, flight);
    }

    return structuredClone(await flight);
}
