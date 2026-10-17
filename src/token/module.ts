import { decodeJwt, decodeProtectedHeader } from 'jose';
import { VouchrError, VouchrErrorCode } from '../error';
import type { ParsedToken } from './types';

const COMPACT_TOKEN_REGEX = /^[\w-]+\.[\w-]+\.[\w-]+$/;

export function isCompactToken(token: string): boolean {
    return COMPACT_TOKEN_REGEX.test(token);
}

function isPlainObject(input: unknown): input is Record<string, unknown> {
    return typeof input === 'object' && input !== null && !Array.isArray(input);
}

export function parseToken(token: string): ParsedToken {
    if (typeof token !== 'string' || !isCompactToken(token)) {
        throw new VouchrError(VouchrErrorCode.TOKEN_MALFORMED, 'The token is not a compact JWS.');
    }

    let header: ParsedToken['header'];
    let claims: ParsedToken['claims'];
    try {
        header = decodeProtectedHeader(token);
        claims = decodeJwt(token);
    } catch (e) {
        throw new VouchrError(VouchrErrorCode.TOKEN_MALFORMED, 'The token could not be decoded.', { cause: e });
    }

    if (!isPlainObject(header) || !isPlainObject(claims)) {
        throw new VouchrError(VouchrErrorCode.TOKEN_MALFORMED, 'The token header or claims are not an object.');
    }

    return {
        raw: token,
        header,
        claims,
    };
}
