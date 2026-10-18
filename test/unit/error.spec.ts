import { describe, expect, it } from 'vitest';
import { VouchrError, VouchrErrorCode, isVouchrError } from '../../src';

describe('src/error', () => {
    it('should recognize a VouchrError', () => {
        const error = new VouchrError(VouchrErrorCode.TOKEN_MALFORMED);
        expect(isVouchrError(error)).toBe(true);
        expect(error).toBeInstanceOf(Error);
        expect(error.code).toBe(VouchrErrorCode.TOKEN_MALFORMED);
        expect(error.message.length).toBeGreaterThan(0);
    });

    it('should keep the cause', () => {
        const cause = new Error('boom');
        const error = new VouchrError(VouchrErrorCode.KEY_UNAVAILABLE, 'no key', { cause });
        expect(error.cause).toBe(cause);
        expect(error.message).toBe('no key');
    });

    it('should recognize a plain object carrying the marker', () => {
        const input = { [Symbol.for('vouchr.error')]: true, code: VouchrErrorCode.TOKEN_EXPIRED };
        expect(isVouchrError(input)).toBe(true);
    });

    it('should not recognize other values', () => {
        expect(isVouchrError(new Error())).toBe(false);
        expect(isVouchrError(null)).toBe(false);
        expect(isVouchrError('token_malformed')).toBe(false);
    });
});
