import type { CryptoKey, JWTPayload } from 'jose';
import { errors, jwtVerify } from 'jose';
import type { ITokenCache, TokenCacheEntry } from '../cache';
import { MemoryTokenCache, hashToken } from '../cache';
import { VouchrError, VouchrErrorCode, isVouchrError } from '../error';
import type { Issuer } from '../issuer';
import { selectIssuer } from '../issuer';
import type { KeySource } from '../key';
import { discovery, resolveVerificationKey } from '../key';
import type { ParsedToken } from '../token';
import { isCompactToken, parseToken } from '../token';
import { resolveCertificateBinding } from './binding';
import type {
    IVerifier,
    VerifierOptions,
    VerifyOptions,
    VerifyResult,
} from './types';

type IssuerRecord = {
    /**
     * Issuer.id, or the issuer's index when it has none; the cache entry's issuer.
     */
    name: string,
    issuer: Issuer,
    keys?: KeySource,
};

const EC_ALGORITHMS : Record<string, string> = {
    'P-256': 'ES256',
    'P-384': 'ES384',
    'P-521': 'ES512',
};

/**
 * The JWS algorithms a resolved key verifies, derived from the key itself so
 * a token's header can never pick another one.
 */
function deriveAlgorithms(key: CryptoKey) : string[] {
    const algorithm = key.algorithm as KeyAlgorithm & { hash?: { name: string }, namedCurve?: string };
    const bits = algorithm.hash?.name.replace('SHA-', '');

    switch (algorithm.name) {
        case 'RSASSA-PKCS1-v1_5':
            return bits ? [`RS${bits}`] : [];
        case 'RSA-PSS':
            return bits ? [`PS${bits}`] : [];
        case 'ECDSA': {
            const alg = algorithm.namedCurve ? EC_ALGORITHMS[algorithm.namedCurve] : undefined;
            return alg ? [alg] : [];
        }
        case 'Ed25519':
            return ['EdDSA', 'Ed25519'];
        default:
            return [];
    }
}

function mapJoseError(e: unknown) : VouchrError {
    if (isVouchrError(e)) {
        return e;
    }

    const message = e instanceof Error && e.message ? e.message : undefined;

    if (e instanceof errors.JWTExpired) {
        return new VouchrError(VouchrErrorCode.TOKEN_EXPIRED, message, { cause: e });
    }

    if (e instanceof errors.JWSSignatureVerificationFailed) {
        return new VouchrError(VouchrErrorCode.SIGNATURE_INVALID, message, { cause: e });
    }

    if (
        e instanceof errors.JWTClaimValidationFailed ||
        e instanceof errors.JOSEAlgNotAllowed ||
        e instanceof errors.JWTInvalid
    ) {
        return new VouchrError(VouchrErrorCode.CLAIM_INVALID, message, { cause: e });
    }

    return new VouchrError(VouchrErrorCode.SIGNATURE_INVALID, message, { cause: e });
}

function buildRecords(options: VerifierOptions) : IssuerRecord[] {
    if (!Array.isArray(options.issuers) || options.issuers.length === 0) {
        throw new TypeError('A verifier needs at least one issuer.');
    }

    const names = new Set<string>();

    return options.issuers.map((issuer, index) => {
        const name = issuer.id ?? String(index);
        if (names.has(name)) {
            throw new TypeError(`The issuer id "${name}" is used twice (an issuer without id is named by its index).`);
        }
        names.add(name);

        const verification = issuer.verification ?? 'local';
        if (verification !== 'local' && verification !== 'introspection') {
            throw new TypeError(`The issuer "${name}" has an unknown verification "${String(verification)}".`);
        }

        let { keys } = issuer;
        if (!keys && verification === 'local') {
            if (typeof issuer.issuer !== 'string') {
                throw new TypeError(
                    `The issuer "${name}" matches by function and needs a key source, since it cannot be discovered.`,
                );
            }

            keys = discovery();
        }

        return {
            name, 
            issuer, 
            keys, 
        };
    });
}

export class Verifier implements IVerifier {
    protected records: IssuerRecord[];

    protected cache: ITokenCache | undefined;

    protected fetch: typeof fetch;

    protected opaque: IssuerRecord | undefined;

    constructor(options: VerifierOptions) {
        this.records = buildRecords(options);

        if (typeof options.opaque !== 'undefined') {
            this.opaque = this.records.find((record) => record.issuer.id === options.opaque);
            if (!this.opaque) {
                throw new TypeError(`The opaque issuer "${options.opaque}" names no configured issuer.`);
            }
        }

        this.cache = options.cache === false ? undefined : (options.cache ?? new MemoryTokenCache());

        // One stable function per verifier: key sources memoise per fetch.
        const fetchFn = options.fetch;
        this.fetch = fetchFn ?? ((input, init) => fetch(input, init));
    }

    async verify(token: string, options: VerifyOptions = {}) : Promise<VerifyResult> {
        const compact = typeof token === 'string' && isCompactToken(token);
        if (!compact && (!this.opaque || typeof token !== 'string' || token.length === 0)) {
            throw new VouchrError(VouchrErrorCode.TOKEN_MALFORMED, 'The token is not a compact JWS.');
        }

        const key = await hashToken(token);

        const cached = await this.readCache(key);
        if (cached) {
            await resolveCertificateBinding(cached.entry.claims, options);

            return {
                claims: structuredClone(cached.entry.claims),
                issuer: cached.record.issuer,
                source: cached.entry.source,
            };
        }

        if (!compact) {
            return this.introspect(token, key, this.opaque!, options);
        }

        const parsed = parseToken(token);

        const index = selectIssuer(this.records.map((record) => record.issuer), parsed.claims);
        if (index === -1) {
            throw new VouchrError(VouchrErrorCode.ISSUER_UNTRUSTED, 'The token issuer is not trusted.');
        }

        const record = this.records[index]!;
        if (record.issuer.verification === 'introspection') {
            return this.introspect(token, key, record, options);
        }

        const claims = await this.verifyLocal(parsed, record);

        await this.writeCache(key, {
            claims, 
            issuer: record.name, 
            source: 'local', 
        }, claims.exp);

        await resolveCertificateBinding(claims, options);

        return {
            claims: structuredClone(claims),
            issuer: record.issuer,
            source: 'local',
        };
    }

    protected async verifyLocal(token: ParsedToken, record: IssuerRecord) : Promise<JWTPayload> {
        const { issuer } = record;

        const key = await resolveVerificationKey(record.keys!, {
            token,
            issuer,
            fetch: this.fetch,
        });

        const algorithms = issuer.algorithms ?? deriveAlgorithms(key);
        if (algorithms.length === 0) {
            throw new VouchrError(VouchrErrorCode.KEY_UNAVAILABLE, 'The verification key has no supported algorithm.');
        }

        let payload : JWTPayload;
        try {
            const output = await jwtVerify(token.raw, key, {
                algorithms,
                audience: issuer.audience,
                typ: issuer.typ,
                clockTolerance: issuer.clockTolerance ?? 0,
                requiredClaims: issuer.requiredClaims ?? ['exp'],
                issuer: typeof issuer.issuer === 'string' ? issuer.issuer : undefined,
            });
            payload = output.payload;
        } catch (e) {
            throw mapJoseError(e);
        }

        await this.assertClaimsPredicate(issuer, payload);

        return payload;
    }

    protected async assertClaimsPredicate(issuer: Issuer, claims: JWTPayload) : Promise<void> {
        if (!issuer.claims) {
            return;
        }

        let passed : boolean;
        try {
            passed = await issuer.claims(structuredClone(claims)) === true;
        } catch (e) {
            throw new VouchrError(VouchrErrorCode.CLAIM_INVALID, 'The claims predicate failed.', { cause: e });
        }

        if (!passed) {
            throw new VouchrError(VouchrErrorCode.CLAIM_INVALID, 'The claims predicate refused the token.');
        }
    }

    /**
     * Verifies a token by RFC 7662 introspection and answers its claims.
     */
    protected async verifyIntrospection(
        _token: string,
        record: IssuerRecord,
    ) : Promise<JWTPayload> {
        throw new VouchrError(
            VouchrErrorCode.INTROSPECTION_FAILED,
            `The issuer "${record.name}" is verified by introspection, which is not available.`,
        );
    }

    protected async introspect(token: string, key: string, record: IssuerRecord, options: VerifyOptions) : Promise<VerifyResult> {
        const claims = await this.verifyIntrospection(token, record);

        await this.writeCache(
            key,
            {
                claims, 
                issuer: record.name, 
                source: 'introspection', 
            },
            claims.exp,
            record.issuer.introspection?.maxCacheTTL,
        );

        await resolveCertificateBinding(claims, options);

        return {
            claims: structuredClone(claims),
            issuer: record.issuer,
            source: 'introspection',
        };
    }

    /**
     * A cache failure is a miss: the token is verified again instead.
     */
    protected async readCache(key: string) : Promise<{ entry: TokenCacheEntry, record: IssuerRecord } | undefined> {
        if (!this.cache) {
            return undefined;
        }

        let entry : TokenCacheEntry | undefined;
        try {
            entry = await this.cache.get(key);
        } catch {
            return undefined;
        }

        if (!entry) {
            return undefined;
        }

        const record = this.records.find((item) => item.name === entry.issuer);
        if (!record) {
            return undefined;
        }

        return { entry, record };
    }

    /**
     * Caches until `exp`, or for at most `maxTTL` seconds when given. A token
     * without `exp` is cached only under a `maxTTL`. A cache failure is ignored.
     */
    protected async writeCache(key: string, entry: TokenCacheEntry, exp: unknown, maxTTL?: number) : Promise<void> {
        if (!this.cache) {
            return;
        }

        let ttl : number | undefined;
        if (typeof exp === 'number' && Number.isFinite(exp)) {
            ttl = exp - Math.floor(Date.now() / 1000);
        }

        if (typeof maxTTL === 'number') {
            ttl = typeof ttl === 'number' ? Math.min(ttl, maxTTL) : maxTTL;
        }

        if (typeof ttl !== 'number' || !(ttl > 0)) {
            return;
        }

        try {
            await this.cache.set(key, structuredClone(entry), ttl);
        } catch {
            // the result stays valid without a cache entry
        }
    }
}

export function createVerifier(options: VerifierOptions) : Verifier {
    return new Verifier(options);
}
