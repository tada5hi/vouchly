import type { JWTPayload } from 'jose';
import { fetchProviderMetadata } from '../discovery';
import { VouchlyError, VouchlyErrorCode, isVouchlyError } from '../error';
import type { Issuer } from '../issuer';
import {
    abortable,
    combineSignals,
    createTimeoutError,
    createTimeoutSignal,
    resolveTimeout,
} from '../signal';
import type { IntrospectOptions, IntrospectionResponse } from './types';

function fail(message: string, cause?: unknown) : VouchlyError {
    return new VouchlyError(VouchlyErrorCode.INTROSPECTION_FAILED, message, typeof cause === 'undefined' ? undefined : { cause });
}

/**
 * application/x-www-form-urlencoded, as RFC 6749 2.3.1 asks for client credentials.
 */
function formEncode(value: string) : string {
    return new URLSearchParams([['', value]]).toString().slice(1);
}

type RequestOptions = {
    timeout: number,
    signal?: AbortSignal,
};

type Answer = {
    status: number,
    ok: boolean,
    body?: string,
};

async function resolveEndpoint(issuer: Issuer, fetchFn: typeof globalThis.fetch, options: RequestOptions) : Promise<string> {
    if (issuer.introspection?.endpoint) {
        return issuer.introspection.endpoint;
    }

    // A function issuer has no configured URL; the token's own `iss` is never fetched.
    if (typeof issuer.issuer !== 'string') {
        throw fail('The issuer has no introspection endpoint.');
    }

    let endpoint : string | undefined;

    try {
        endpoint = (await fetchProviderMetadata(issuer.issuer, fetchFn, { timeout: options.timeout, signal: options.signal })).introspection_endpoint;
    } catch (e) {
        if (isVouchlyError(e) && e.code === VouchlyErrorCode.TIMEOUT) {
            throw e;
        }

        throw fail('The introspection endpoint could not be discovered.', e);
    }

    if (!endpoint) {
        throw fail('The issuer advertises no introspection endpoint.');
    }

    return endpoint;
}

async function resolveAuthorization(issuer: Issuer, retry: boolean) : Promise<string | undefined> {
    const authorization = issuer.introspection?.authorization;

    if (!authorization) {
        return undefined;
    }

    if (typeof authorization === 'function') {
        try {
            return await authorization({ retry });
        } catch (e) {
            throw fail('The introspection authorization could not be resolved.', e);
        }
    }

    return `Basic ${btoa(`${formEncode(authorization.clientId)}:${formEncode(authorization.clientSecret)}`)}`;
}

function isResponse(input: unknown) : input is IntrospectionResponse {
    return typeof input === 'object' && input !== null && !Array.isArray(input);
}

/**
 * One request, its body read within the same time limit.
 */
async function send(
    token: string,
    endpoint: string,
    authorization: string | undefined,
    fetchFn: typeof globalThis.fetch,
    options: RequestOptions,
) : Promise<Answer> {
    const headers : Record<string, string> = {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
    };

    if (typeof authorization === 'string') {
        headers.authorization = authorization;
    }

    const timer = createTimeoutSignal(options.timeout);

    try {
        const response = await fetchFn(endpoint, {
            method: 'POST',
            headers,
            body: new URLSearchParams({ token }).toString(),
            signal: combineSignals(timer.signal, options.signal),
        });

        if (!response.ok) {
            // not awaited: discarding the body must not hold back the answer
            response.body?.cancel().catch(() => undefined);

            return { status: response.status, ok: false };
        }

        return {
            status: response.status, 
            ok: true, 
            body: await response.text(), 
        };
    } catch (e) {
        if (options.signal?.aborted) {
            throw options.signal.reason;
        }

        if (timer.signal.aborted) {
            throw createTimeoutError('The introspection request timed out.', e);
        }

        throw fail('The introspection request failed.', e);
    } finally {
        timer.clear();
    }
}

async function request(
    token: string,
    issuer: Issuer,
    fetchFn: typeof globalThis.fetch,
    options: RequestOptions,
) : Promise<JWTPayload> {
    const endpoint = await resolveEndpoint(issuer, fetchFn, options);

    let answer = await send(token, endpoint, await abortable(resolveAuthorization(issuer, false), options.signal), fetchFn, options);

    // A function may hold a token that expired since it was minted; it gets
    // one chance to mint a fresh one. Client credentials would only repeat.
    if (answer.status === 401 && typeof issuer.introspection?.authorization === 'function') {
        answer = await send(token, endpoint, await abortable(resolveAuthorization(issuer, true), options.signal), fetchFn, options);
    }

    if (!answer.ok) {
        throw new VouchlyError(
            VouchlyErrorCode.INTROSPECTION_FAILED,
            `The introspection endpoint answered ${answer.status}.`,
            { status: answer.status },
        );
    }

    let body : unknown;

    try {
        body = JSON.parse(answer.body ?? '');
    } catch (e) {
        throw fail('The introspection response is not JSON.', e);
    }

    if (!isResponse(body)) {
        throw fail('The introspection response is not a JSON object.');
    }

    if (body.active !== true) {
        throw new VouchlyError(VouchlyErrorCode.TOKEN_INACTIVE, 'The token is not active.');
    }

    return body as JWTPayload;
}

/**
 * RFC 7662: asks the issuer's introspection endpoint about a token and
 * answers the response as its claims. Claim rules are the caller's.
 */
export async function introspect(
    token: string,
    issuer: Issuer,
    fetchFn: typeof globalThis.fetch,
    options: IntrospectOptions = {},
) : Promise<JWTPayload> {
    const timeout = resolveTimeout(options.timeout, 'introspection timeout');
    const { signal } = options;

    signal?.throwIfAborted();

    try {
        return await request(token, issuer, fetchFn, { timeout, signal });
    } catch (e) {
        if (signal?.aborted) {
            throw signal.reason;
        }

        if (isVouchlyError(e)) {
            throw e;
        }

        throw fail('The introspection failed.', e);
    }
}
