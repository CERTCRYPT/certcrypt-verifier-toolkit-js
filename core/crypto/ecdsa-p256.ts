/**
 * ECDSA P-256 (secp256r1) signature verification — the classical component of
 * the CERTCRYPT Composite Signature Profile (`certcrypt-composite-p256-mldsa65-v1`).
 *
 * This module is a low-level cryptographic PRIMITIVE. It MUST NOT be used as a
 * signature-verdict API on its own: a composite signature is valid only through
 * `verifyComposite` (AND of all components), as `composite-signature/1` requires.
 *
 * Canonical wire form:
 *   - curve P-256 / secp256r1, hash **SHA3-256** over the signed message
 *     (CERTCRYPT's stack-wide hash — NOT SHA-2; ECDSA is hash-agnostic);
 *   - signature encoding `raw-rs-64`: r || s, 64 bytes (32+32), NOT DER;
 *   - low-s NORMATIVE: a high-s signature is REJECTED (not normalized).
 *
 * The digest is applied by the active crypto provider, which hashes the MESSAGE
 * with SHA3-256 (matching the reference producer's digest reduced mod n) rather than
 * accepting a pre-computed digest under a null algorithm, which does not
 * interoperate.
 *
 * Public key: this primitive decodes a raw SEC1 point or SPKI DER. Which ONE
 * encoding a key field admits is fixed by the artifact that carries it, and the
 * composite verifier enforces it before calling here (`verifyComposite`: SEC1
 * uncompressed, 65 bytes, for every P-256 field of the corpus).
 *
 * The low-s gate below is enforced HERE, not in a backend, so the normative
 * anti-malleability rule is applied identically on every runtime.
 */
import { getCryptoProvider } from "./provider/index.js";
import { strictBase64Decode } from "./provider/bytes.js";

// secp256r1 group order n, and n/2 (the low-s ceiling, inclusive).
const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

/**
 * Verify an ECDSA P-256 signature over `payloadBytes` (raw message; SHA3-256 is
 * applied internally, matching the signer).
 *
 * @param publicKeyB64 RFC 4648 base64 public key (SEC1 raw or SPKI DER).
 * @param payloadBytes the exact message bytes that were signed (e.g. `M'`).
 * @param signatureB64 RFC 4648 base64 signature in `raw-rs-64` form (64 bytes).
 * @returns true iff the signature verifies AND is low-s. A high-s signature
 *   returns false (rejected, never normalized).
 * @throws on malformed encoding, wrong signature length, or a crypto runtime error.
 */
export function verifyEcdsaP256Signature(
  publicKeyB64: string,
  payloadBytes: Uint8Array,
  signatureB64: string
): boolean {
  const pubKeyBytes = strictBase64Decode(publicKeyB64, "public_key");
  const sigBytes = strictBase64Decode(signatureB64, "signature");

  if (sigBytes.length !== 64) {
    throw new Error(
      `ECDSA-P256 signature must be raw-rs-64 (64 bytes r||s), got ${sigBytes.length} bytes`
    );
  }

  // Low-s gate FIRST: reject high-s outright (anti-malleability, normative).
  // s is the second 32-byte half.
  const s = beBytesToBigInt(sigBytes.subarray(32, 64));
  if (s > P256_HALF_N || s === 0n) {
    return false;
  }
  // r must also be in [1, n-1] for a well-formed signature.
  const r = beBytesToBigInt(sigBytes.subarray(0, 32));
  if (r === 0n || r >= P256_N) {
    return false;
  }

  return getCryptoProvider().verifyEcdsaP256Sha3(
    pubKeyBytes,
    payloadBytes,
    sigBytes
  );
}

function beBytesToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (const b of bytes) {
    acc = (acc << 8n) | BigInt(b);
  }
  return acc;
}
