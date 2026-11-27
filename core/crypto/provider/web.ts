/**
 * Web backend — `@noble/hashes` + `@noble/curves`.
 *
 * For runtimes without `node:crypto`: browsers, Deno, edge workers. The reason
 * this exists is not portability for its own sake — it is that computing an
 * artifact's commitment requires the ORIGINAL MATERIAL, and sending that to a
 * server would transmit exactly the private content the protocol is designed
 * never to require. A verifier that runs in the browser keeps the material on
 * the user's machine.
 *
 * WebCrypto is not sufficient here: it has no SHA-3 at all, and SHA3-256 is the
 * digest under every commitment in the spec. Hence @noble, which the toolkit
 * already depends on for ML-DSA-65.
 *
 * Equivalence with the Node backend is not assumed — `provider.equivalence.test.ts`
 * asserts it primitive by primitive, and the conformance suite runs against both.
 */
import { sha3_256 as nobleSha3_256 } from "@noble/hashes/sha3.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { ecdsa } from "@noble/curves/abstract/weierstrass.js";
import type { CryptoProvider, Sha3Stream } from "./types.js";

/**
 * P-256 with SHA3-256 as the ECDSA hash.
 *
 * noble's stock `p256` is bound to SHA-256, and its API gives no way to verify
 * a signature over a foreign digest: passing a pre-computed hash as the message
 * makes it hash AGAIN, so a valid signature is rejected. Rebuilding the curve
 * over `sha3_256` is what makes `prehash: true` apply the right digest — and it
 * is what interoperates with node's `verify("sha3-256", …)` and the reference signer,
 * verified in both directions by `provider.equivalence.test.ts`.
 */
const p256Sha3 = ecdsa(p256.Point, nobleSha3_256);

/**
 * Ed25519 keys arrive raw (32 bytes) or SPKI DER (44 bytes, the 12-byte prefix
 * then the key). noble takes the raw point, so DER is unwrapped by length —
 * the prefix is fixed for Ed25519, so there is nothing to parse.
 */
function ed25519RawKey(publicKey: Uint8Array): Uint8Array {
  if (publicKey.length === 32) return publicKey;
  if (publicKey.length === 44) return publicKey.subarray(12);
  throw new Error(
    `Ed25519 public key must be 32 bytes (raw) or valid SPKI DER, got ${publicKey.length} bytes`
  );
}

/**
 * P-256 keys arrive as a raw SEC1 point — uncompressed (65B, 0x04) or compressed
 * (33B, 0x02/0x03) — or wrapped in SPKI DER. noble accepts either point form
 * directly and decompresses internally, so DER is unwrapped by taking the
 * trailing point: the AlgorithmIdentifier prefix is fixed for P-256, and the
 * point length is what varies (91 = 26 + 65 uncompressed, 59 = 26 + 33 compressed).
 */
function p256RawKey(publicKey: Uint8Array): Uint8Array {
  const first = publicKey[0];
  if (publicKey.length === 65 && first === 0x04) return publicKey;
  if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
    return publicKey;
  }
  if (publicKey.length === 91) {
    const point = publicKey.subarray(publicKey.length - 65);
    if (point[0] === 0x04) return point;
  }
  if (publicKey.length === 59) {
    const point = publicKey.subarray(publicKey.length - 33);
    if (point[0] === 0x02 || point[0] === 0x03) return point;
  }
  throw new Error(
    `ECDSA-P256 public key must be SEC1 uncompressed (65B) or SPKI DER, got ${publicKey.length} bytes`
  );
}

export const webProvider: CryptoProvider = {
  backend: "web",

  sha3_256(data: Uint8Array): Uint8Array {
    return nobleSha3_256(data);
  },

  sha3_256_stream(): Sha3Stream {
    // noble's `create()` runs the same permutation as the one-shot call above, so a streamed
    // digest and a whole-buffer digest of the same bytes are equal by construction; the
    // equivalence test pins it against node's backend as well.
    const h = nobleSha3_256.create();
    return {
      update: (chunk: Uint8Array) => {
        h.update(chunk);
      },
      digest: () => new Uint8Array(h.digest())
    };
  },

  verifyEd25519(publicKey, message, signature): boolean {
    const key = ed25519RawKey(publicKey);
    // A malformed signature must be a false verdict, not a throw — the Node
    // backend returns false for these, and the two must agree.
    try {
      return ed25519.verify(signature, message, key);
    } catch {
      return false;
    }
  },

  verifyEcdsaP256Sha3(publicKey, message, signature): boolean {
    const key = p256RawKey(publicKey);
    try {
      // `lowS: false` is REQUIRED for parity, not a relaxation. noble rejects
      // high-s by default while node:crypto does not, so leaving the default on
      // would make this backend reject signatures the Node backend accepts —
      // half of all signatures, since s is high roughly half the time.
      //
      // The low-s rule is still enforced, and more visibly: `ecdsa-p256.ts`
      // gates it before calling any backend, so the normative anti-malleability
      // check lives in ONE place and applies identically on every runtime.
      // Enforcing it here as well would hide the rule inside a dependency's
      // default.
      return p256Sha3.verify(signature, message, key, {
        prehash: true,
        lowS: false,
      });
    } catch {
      return false;
    }
  },
};
