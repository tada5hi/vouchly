import type { JWTPayload } from 'jose';
import type { Issuer } from './types';

/**
 * Whether an issuer config trusts a token by its UNVERIFIED claims. This only
 * selects a config: verification still runs against it afterwards. A
 * function matcher counts only when it returns exactly `true`; one that
 * throws, or returns anything else (a Promise included), does not match.
 */
export function matchIssuer(issuer: Issuer, claims: JWTPayload) : boolean {
    if (typeof issuer.issuer === 'string') {
        return typeof claims.iss === 'string' && claims.iss === issuer.issuer;
    }

    try {
        return issuer.issuer(claims) === true;
    } catch {
        return false;
    }
}

/**
 * The index of the first issuer that trusts the claims, or -1.
 */
export function selectIssuer(issuers: Issuer[], claims: JWTPayload) : number {
    for (const [index, issuer] of issuers.entries()) {
        if (matchIssuer(issuer, claims)) {
            return index;
        }
    }

    return -1;
}
