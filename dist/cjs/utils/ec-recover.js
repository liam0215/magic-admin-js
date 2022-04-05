"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var keccak_1 = require("ethereum-cryptography/keccak");
var secp256k1_compat_1 = require("ethereum-cryptography/secp256k1-compat");
var utils_1 = require("ethereum-cryptography/utils");
function hashPersonalMessage(message) {
    var prefix = utf8ToBytes("\u0019Ethereum Signed Message:\n" + message.length);
    var totalLength = prefix.length + message.length;
    var output = new Uint8Array(totalLength);
    output.set(prefix);
    output.set(message, prefix.length);
    return keccak_1.keccak256(output);
}
function getRecoveryBit(signature) {
    var bit = signature[64];
    return bit - 27;
}
function prepareSignature(signature) {
    return signature.slice(2); // strip the `0x` prefix
}
function publicKeyToAddress(publicKey) {
    var address = keccak_1.keccak256(publicKey.slice(1)).slice(-20);
    return "0x" + utils_1.bytesToHex(address);
}
function utf8ToBytes(str) {
    // TODO(user): Use native implementations if/when available
    var out = new Uint8Array();
    var p = 0;
    for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 128) {
            out[p++] = c;
        }
        else if (c < 2048) {
            out[p++] = (c >> 6) | 192;
            out[p++] = (c & 63) | 128;
        }
        else if (((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
            ((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
            // Surrogate Pair
            c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
            out[p++] = (c >> 18) | 240;
            out[p++] = ((c >> 12) & 63) | 128;
            out[p++] = ((c >> 6) & 63) | 128;
            out[p++] = (c & 63) | 128;
        }
        else {
            out[p++] = (c >> 12) | 224;
            out[p++] = ((c >> 6) & 63) | 128;
            out[p++] = (c & 63) | 128;
        }
    }
    return out;
}
/**
 * Recover the signer from an Elliptic Curve signature.
 */
function ecRecover(data, signature) {
    // Use ecdsaRecover on the Proof, to validate if it recovers to the expected
    // Claim, and expected Signer Address.
    var msg = utf8ToBytes(data);
    var sig = utils_1.hexToBytes(prepareSignature(signature));
    var recovery = getRecoveryBit(sig);
    var hash = hashPersonalMessage(msg);
    var publicKey = secp256k1_compat_1.ecdsaRecover(sig.slice(0, 64), recovery, hash, false);
    var assertPublicKey = secp256k1_compat_1.publicKeyConvert(publicKey, false);
    return publicKeyToAddress(assertPublicKey);
}
exports.ecRecover = ecRecover;
//# sourceMappingURL=ec-recover.js.map