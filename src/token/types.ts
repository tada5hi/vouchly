import type { JWTPayload, ProtectedHeaderParameters } from 'jose';

export type ParsedToken = {
    raw: string,
    header: ProtectedHeaderParameters,
    claims: JWTPayload,
};
