import { describe, expect, it } from 'vitest';
import { VouchlyError, VouchlyErrorCode, isVouchlyError } from '../../src';

describe('src/error', () => {
    it('should recognize a VouchlyError', () => {
        const error = new VouchlyError(VouchlyErrorCode.TOKEN_MALFORMED);
        expect(isVouchlyError(error)).toBe(true);
        expect(error).toBeInstanceOf(Error);
        expect(error.code).toBe(VouchlyErrorCode.TOKEN_MALFORMED);
        expect(error.message.length).toBeGreaterThan(0);
    });

    it('should keep the cause', () => {
        const cause = new Error('boom');
        const error = new VouchlyError(VouchlyErrorCode.KEY_UNAVAILABLE, 'no key', { cause });
        expect(error.cause).toBe(cause);
        expect(error.message).toBe('no key');
    });

    it('should recognize a plain object carrying the marker', () => {
        const input = { [Symbol.for('vouchly.error')]: true, code: VouchlyErrorCode.TOKEN_EXPIRED };
        expect(isVouchlyError(input)).toBe(true);
    });

    it('should not recognize other values', () => {
        expect(isVouchlyError(new Error())).toBe(false);
        expect(isVouchlyError(null)).toBe(false);
        expect(isVouchlyError('token_malformed')).toBe(false);
    });
});
