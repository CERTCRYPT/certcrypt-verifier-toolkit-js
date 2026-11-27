/**
 * Node backend — `node:crypto`.
 *
 * The default wherever `node:crypto` is reachable: the CLI, the test suite and
 * the conformance harness run on these primitives, and the Web backend is held
 * to the same acceptance and rejection conditions by the equivalence test.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import type { CryptoProvider, Sha3Stream } from "./types.js";
import { concatBytes, fromHex } from "./bytes.js";

// SPKI DER prefix that wraps a raw 32-byte Ed25519 public key.
const ED25519_SPKI_PREFIX = fromHex("302a300506032b6570032100");

function importEd25519PublicKey(pubKeyBytes: Uint8Array) {
  // SPKI DER first; a raw 32-byte key is the documented fallback.
  try {
    return createPublicKey({
      key: Buffer.from(pubKeyBytes),
      format: "der",
      type: "spki",
    });
  } catch {
    if (pubKeyBytes.length === 32) {
      return createPublicKey({
        key: Buffer.from(concatBytes(ED25519_SPKI_PREFIX, pubKeyBytes)),
        format: "der",
        type: "spki",
      });
    }
    throw new Error(
      `Ed25519 public key must be 32 bytes (raw) or valid SPKI DER, got ${pubKeyBytes.length} bytes`
    );
  }
}

// The P-256 AlgorithmIdentifier (id-ecPublicKey + prime256v1), constant across
// point encodings. Only the outer SEQUENCE length and BIT STRING length change
// with the point size (33B compressed / 65B uncompressed).
const P256_ALG_ID = fromHex("301306072a8648ce3d020106082a8648ce3d030107");

/** Build the SPKI DER prefix for a SEC1 point of `pointLen` bytes (33 or 65). */
function p256SpkiPrefix(pointLen: number): Uint8Array {
  // BIT STRING: tag 0x03, len = pointLen + 1 (the unused-bits octet 0x00), then 0x00.
  const bitString = new Uint8Array([0x03, pointLen + 1, 0x00]);
  const body = concatBytes(P256_ALG_ID, bitString);
  // Outer SEQUENCE: tag 0x30, len = body.length + pointLen.
  return concatBytes(new Uint8Array([0x30, body.length + pointLen]), body);
}

function importP256PublicKey(pubKeyBytes: Uint8Array) {
  // SPKI DER first.
  try {
    return createPublicKey({
      key: Buffer.from(pubKeyBytes),
      format: "der",
      type: "spki",
    });
  } catch {
    // Raw SEC1 point: compressed (33B, 0x02/0x03) or uncompressed (65B, 0x04).
    const first = pubKeyBytes[0];
    const isCompressed =
      pubKeyBytes.length === 33 && (first === 0x02 || first === 0x03);
    const isUncompressed = pubKeyBytes.length === 65 && first === 0x04;
    if (isUncompressed || isCompressed) {
      // node's OpenSSL decompresses a compressed point on import.
      return createPublicKey({
        key: Buffer.from(
          concatBytes(p256SpkiPrefix(pubKeyBytes.length), pubKeyBytes)
        ),
        format: "der",
        type: "spki",
      });
    }
    throw new Error(
      `ECDSA-P256 public key must be SEC1 uncompressed (65B) or SPKI DER, got ${pubKeyBytes.length} bytes`
    );
  }
}

export const nodeProvider: CryptoProvider = {
  backend: "node",

  sha3_256(data: Uint8Array): Uint8Array {
    return new Uint8Array(createHash("sha3-256").update(data).digest());
  },

  sha3_256_stream(): Sha3Stream {
    // Same primitive as the one-shot form above, so a streamed digest and a whole-buffer
    // digest of the same bytes are the same value by construction rather than by agreement.
    const h = createHash("sha3-256");
    return {
      update: (chunk: Uint8Array) => {
        h.update(chunk);
      },
      digest: () => new Uint8Array(h.digest())
    };
  },

  verifyEd25519(publicKey, message, signature): boolean {
    const keyObject = importEd25519PublicKey(publicKey);
    return cryptoVerify(
      null,
      Buffer.from(message),
      keyObject,
      Buffer.from(signature)
    );
  },

  verifyEcdsaP256Sha3(publicKey, message, signature): boolean {
    const keyObject = importP256PublicKey(publicKey);
    // "sha3-256" — matches the reference signer's digest. "sha256" would be SHA-2 and
    // never match; a manual prehash with a null algorithm does not interoperate.
    return cryptoVerify(
      "sha3-256",
      Buffer.from(message),
      { key: keyObject, dsaEncoding: "ieee-p1363" },
      Buffer.from(signature)
    );
  },
};
