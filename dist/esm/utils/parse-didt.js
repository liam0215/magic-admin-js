import { toByteArray } from 'base64-js';
import { isDIDTClaim } from './type-guards';
import { createMalformedTokenError } from '../core/sdk-exceptions';
function convertUint8ArrayToBinaryString(u8Array) {
    let i;
    const len = u8Array.length;
    let b_str = '';
    for (i = 0; i < len; i++) {
        b_str += String.fromCharCode(u8Array[i]);
    }
    return b_str;
}
/**
 * Parses a DID Token so that the encoded `claim` is in object form.
 */
export function parseDIDToken(DIDToken) {
    try {
        const did_binary_string = convertUint8ArrayToBinaryString(toByteArray(DIDToken));
        const [proof, claim] = JSON.parse(did_binary_string);
        const parsedClaim = JSON.parse(claim);
        if (isDIDTClaim(parsedClaim))
            return { raw: [proof, claim], withParsedClaim: [proof, parsedClaim] };
        throw new Error();
    }
    catch {
        throw createMalformedTokenError();
    }
}
//# sourceMappingURL=parse-didt.js.map