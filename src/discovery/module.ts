import { VouchlyErrorCode, isVouchlyError } from '../error';
import type { DeadlineSignal } from '../signal';
import {
    createDeadlineSignal,
    createTimeoutError,
    resolveTimeout,
    waitWithin,
} from '../signal';
import type { FetchProviderMetadataOptions, ProviderMetadata } from './types';

const CACHE_MAX_AGE = 600;
const FAILURE_COOLDOWN = 30_000;

type MetadataItem = {
    metadata: ProviderMetadata,
    fetchedAt: number,
};

type MetadataFlight = {
    promise: Promise<ProviderMetadata>,
    /**
     * Ends with the latest deadline of the callers that waited for it.
     */
    deadline: DeadlineSignal,
};

type MetadataFailure = {
    failedAt: number,
    timedOut: boolean,
};

// Keyed by fetch implementation, then by the configured issuer string, so
// two verifiers with different fetch functions never share an answer.
const items = new WeakMap<typeof fetch, Map<string, MetadataItem>>();
const flights = new WeakMap<typeof fetch, Map<string, MetadataFlight>>();
const failures = new WeakMap<typeof fetch, Map<string, MetadataFailure>>();

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

async function request(url: string, fetchFn: typeof globalThis.fetch, signal: AbortSignal) : Promise<unknown> {
    try {
        const response = await fetchFn(url, {
            headers: { accept: 'application/json' },
            signal,
        });

        if (!response.ok) {
            throw new Error(`The provider metadata request answered ${response.status}.`);
        }

        return await response.json();
    } catch (e) {
        if (signal.aborted) {
            throw createTimeoutError('The provider metadata request timed out.', e);
        }

        throw e;
    }
}

async function load(issuer: string, fetchFn: typeof globalThis.fetch, signal: AbortSignal) : Promise<ProviderMetadata> {
    const url = `${issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;

    const body : unknown = await request(url, fetchFn, signal);

    if (!isRecord(body)) {
        throw new Error('The provider metadata is not a JSON object.');
    }

    // OIDC Discovery 1.0, section 4.3.
    if (body.issuer !== issuer) {
        throw new Error('The provider metadata names another issuer.');
    }

    const metadata : ProviderMetadata = { issuer: body.issuer };

    if (typeof body.jwks_uri !== 'undefined') {
        if (!isURL(body.jwks_uri)) {
            throw new Error('The provider metadata has an invalid jwks_uri.');
        }

        metadata.jwks_uri = body.jwks_uri;
    }

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
 * cacheMaxAge seconds; after a failure, the issuer is not asked again for
 * 30 seconds and calls fail fast instead, as TIMEOUT after a timeout.
 * Concurrent calls share one request: each waits for at most its own
 * timeout, and the request runs until the latest of their deadlines.
 */
export async function fetchProviderMetadata(
    issuer: string,
    fetchFn: typeof globalThis.fetch,
    options: FetchProviderMetadataOptions = {},
) : Promise<ProviderMetadata> {
    const cacheMaxAge = options.cacheMaxAge ?? CACHE_MAX_AGE;
    const timeout = resolveTimeout(options.timeout, 'discovery timeout');

    options.signal?.throwIfAborted();

    const cached = scope(items, fetchFn);
    const item = cached.get(issuer);

    if (item && Date.now() - item.fetchedAt < cacheMaxAge * 1000) {
        return structuredClone(item.metadata);
    }

    const failed = scope(failures, fetchFn);
    const failure = failed.get(issuer);

    if (failure) {
        if (Date.now() - failure.failedAt < FAILURE_COOLDOWN) {
            const message = 'The provider metadata failed to load recently, not trying again yet.';

            throw failure.timedOut ? createTimeoutError(message, undefined) : new Error(message);
        }

        failed.delete(issuer);
    }

    const deadline = Date.now() + (timeout * 1000);
    const pending = scope(flights, fetchFn);
    let flight = pending.get(issuer);

    if (flight) {
        flight.deadline.extend(deadline);
    } else {
        const bound = createDeadlineSignal(deadline);
        const promise : Promise<ProviderMetadata> = load(issuer, fetchFn, bound.signal)
            .then((metadata) => {
                cached.set(issuer, { metadata, fetchedAt: Date.now() });

                return metadata;
            }, (e: unknown) => {
                failed.set(issuer, {
                    failedAt: Date.now(),
                    timedOut: isVouchlyError(e) && e.code === VouchlyErrorCode.TIMEOUT,
                });

                throw e;
            })
            .finally(() => {
                bound.clear();

                if (pending.get(issuer) === flight) {
                    pending.delete(issuer);
                }
            });

        flight = { promise, deadline: bound };
        pending.set(issuer, flight);
    }

    return structuredClone(await waitWithin(
        flight.promise,
        timeout,
        'The provider metadata request timed out.',
        options.signal,
    ));
}
