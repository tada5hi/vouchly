import type { JWTPayload } from 'jose';
import { VouchrError, VouchrErrorCode } from '../error';
import type { VerifyOptions } from './types';

/**
 * RFC 8705: a token carrying `cnf` is certificate-bound and fails closed
 * unless the presented thumbprint equals `cnf.x5t#S256`. A `cnf` this check
 * cannot satisfy (no `x5t#S256`, e.g. a DPoP `jkt`) fails too.
 */
export function assertCertificateBinding(claims: JWTPayload, thumbprint: string | undefined) : void {
    if (typeof claims.cnf === 'undefined' || claims.cnf === null) {
        return;
    }

    const expected = typeof claims.cnf === 'object' ?
        (claims.cnf as Record<string, unknown>)['x5t#S256'] :
        undefined;

    if (
        typeof expected !== 'string' ||
        expected.length === 0 ||
        typeof thumbprint !== 'string' ||
        thumbprint !== expected
    ) {
        throw new VouchrError(
            VouchrErrorCode.BINDING_MISMATCH,
            'The token is bound to a certificate that was not presented.',
        );
    }
}

function isBound(claims: JWTPayload) : boolean {
    return typeof claims.cnf !== 'undefined' && claims.cnf !== null;
}

/**
 * Checks the binding of every claim set given: a token verified by
 * introspection passes its own unverified claims next to the response, since
 * an unverified `cnf` may only add a requirement, never lift one.
 */
export async function resolveCertificateBinding(
    claims: JWTPayload | JWTPayload[],
    options: VerifyOptions,
) : Promise<void> {
    const bound = (Array.isArray(claims) ? claims : [claims]).filter(isBound);
    if (bound.length === 0) {
        return;
    }

    let thumbprint : string | undefined;
    if (typeof options.certificateThumbprint === 'function') {
        try {
            thumbprint = await options.certificateThumbprint();
        } catch (e) {
            throw new VouchrError(
                VouchrErrorCode.BINDING_MISMATCH,
                'The certificate thumbprint could not be resolved.',
                { cause: e },
            );
        }
    } else {
        thumbprint = options.certificateThumbprint;
    }

    for (const item of bound) {
        assertCertificateBinding(item, thumbprint);
    }
}
