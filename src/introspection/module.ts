import type { JWTPayload } from 'jose';
import { fetchProviderMetadata } from '../discovery';
import { VouchlyError, VouchlyErrorCode, isVouchlyError } from '../error';
import type { Issuer } from '../issuer';
import type { IntrospectionResponse } from './types';

const TIMEOUT = 10_000;

function fail(message: string, cause?: unknown) : VouchlyError {
    return new VouchlyError(VouchlyErrorCode.INTROSPECTION_FAILED, message, typeof cause === 'undefined' ? undefined : { cause });
}

/**
 * application/x-www-form-urlencoded, as RFC 6749 2.3.1 asks for client credentials.
 */
function formEncode(value: string) : string {
    return new URLSearchParams([['', value]]).toString().slice(1);
}

async function resolveEndpoint(issuer: Issuer, fetchFn: typeof globalThis.fetch) : Promise<string> {
    if (issuer.introspection?.endpoint) {
        return issuer.introspection.endpoint;
    }

    // A function issuer has no configured URL; the token's own `iss` is never fetched.
    if (typeof issuer.issuer !== 'string') {
        throw fail('The issuer has no introspection endpoint.');
    }

    let endpoint : string | undefined;
    try {
        endpoint = (await fetchProviderMetadata(issuer.issuer, fetchFn)).introspection_endpoint;
    } catch (e) {
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

async function send(
    token: string,
    endpoint: string,
    authorization: string | undefined,
    fetchFn: typeof globalThis.fetch,
) : Promise<Response> {
    const headers : Record<string, string> = {
        'content-type': 'application/x-www-form-urlencoded',
        accept: 'application/json',
    };
    if (typeof authorization === 'string') {
        headers.authorization = authorization;
    }

    try {
        return await fetchFn(endpoint, {
            method: 'POST',
            headers,
            body: new URLSearchParams({ token }).toString(),
            signal: AbortSignal.timeout(TIMEOUT),
        });
    } catch (e) {
        throw fail('The introspection request failed.', e);
    }
}

async function request(token: string, issuer: Issuer, fetchFn: typeof globalThis.fetch) : Promise<JWTPayload> {
    const endpoint = await resolveEndpoint(issuer, fetchFn);

    let response = await send(token, endpoint, await resolveAuthorization(issuer, false), fetchFn);

    // A function may hold a token that expired since it was minted; it gets
    // one chance to mint a fresh one. Client credentials would only repeat.
    if (response.status === 401 && typeof issuer.introspection?.authorization === 'function') {
        await response.body?.cancel().catch(() => undefined);
        response = await send(token, endpoint, await resolveAuthorization(issuer, true), fetchFn);
    }

    if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        throw new VouchlyError(
            VouchlyErrorCode.INTROSPECTION_FAILED,
            `The introspection endpoint answered ${response.status}.`,
            { status: response.status },
        );
    }

    let body : unknown;
    try {
        body = JSON.parse(await response.text());
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
) : Promise<JWTPayload> {
    try {
        return await request(token, issuer, fetchFn);
    } catch (e) {
        if (isVouchlyError(e)) {
            throw e;
        }

        throw fail('The introspection failed.', e);
    }
}
