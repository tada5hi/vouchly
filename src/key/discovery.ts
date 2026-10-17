import type { DiscoveryOptions } from '../discovery';
import { fetchProviderMetadata } from '../discovery';
import { VouchrError, VouchrErrorCode } from '../error';
import { jwks } from './jwks';
import type { KeySource } from './types';

/**
 * Resolves keys through the configured issuer's OIDC discovery document.
 * A function issuer is refused: its only URL would be the token's own `iss`.
 */
export function discovery(options: DiscoveryOptions = {}) : KeySource {
    if (
        typeof options.cacheMaxAge !== 'undefined' &&
        (!Number.isFinite(options.cacheMaxAge) || options.cacheMaxAge < 0)
    ) {
        throw new TypeError('The discovery cacheMaxAge must be a finite, non-negative number of seconds.');
    }

    const sources = new Map<string, KeySource>();

    return async (context) => {
        const { issuer } = context.issuer;
        if (typeof issuer !== 'string') {
            throw new VouchrError(
                VouchrErrorCode.KEY_UNAVAILABLE,
                'Discovery needs a configured issuer string, a function issuer cannot be discovered.',
            );
        }

        let metadata;
        try {
            metadata = await fetchProviderMetadata(issuer, context.fetch, options);
        } catch (e) {
            const message = e instanceof Error && e.message ? e.message : 'The provider metadata is unavailable.';
            throw new VouchrError(VouchrErrorCode.KEY_UNAVAILABLE, message, { cause: e });
        }

        let source = sources.get(metadata.jwks_uri);
        if (!source) {
            source = jwks(metadata.jwks_uri);
            sources.set(metadata.jwks_uri, source);
        }

        return source(context);
    };
}
