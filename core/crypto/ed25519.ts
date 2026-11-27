/**
 * Ed25519 signature verification.
 *
 * Supports both raw 32-byte public keys and SPKI DER-encoded keys.
 * Strict RFC 4648 base64 decoding for all inputs.
 *
 * The primitive itself comes from the active crypto provider (node:crypto or
 * @noble), so this path runs unchanged in a browser. Base64 strictness lives
 * here rather than in a backend: it is a rule of the input format, identical on
 * every runtime.
 */
import { getCryptoProvider } from "./provider/index.js";
import { strictBase64Decode } from "./provider/bytes.js";

/**
 * Verify an Ed25519 signature.
 *
 * @param publicKeyB64 - RFC 4648 base64-encoded public key (raw 32 bytes or SPKI DER)
 * @param payloadBytes - The exact bytes that were signed
 * @param signatureB64 - RFC 4648 base64-encoded signature
 * @returns true if valid, false if invalid
 * @throws on malformed encoding or crypto runtime errors
 */
export function verifyEd25519Signature(
  publicKeyB64: string,
  payloadBytes: Uint8Array,
  signatureB64: string
): boolean {
  const pubKeyBytes = strictBase64Decode(publicKeyB64, "public_key");
  const sigBytes = strictBase64Decode(signatureB64, "signature");

  return getCryptoProvider().verifyEd25519(pubKeyBytes, payloadBytes, sigBytes);
}
