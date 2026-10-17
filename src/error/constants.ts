export enum VouchrErrorCode {
    TOKEN_MALFORMED = 'token_malformed',
    TOKEN_EXPIRED = 'token_expired',
    TOKEN_INACTIVE = 'token_inactive',
    ISSUER_UNTRUSTED = 'issuer_untrusted',
    KEY_UNAVAILABLE = 'key_unavailable',
    SIGNATURE_INVALID = 'signature_invalid',
    CLAIM_INVALID = 'claim_invalid',
    INTROSPECTION_FAILED = 'introspection_failed',
    BINDING_MISMATCH = 'binding_mismatch',
}

export const VOUCHR_ERROR_MARKER = Symbol.for('vouchr.error');
