/**
 * Operation-scoped pseudonyms — byte-for-byte with the reference producer, as
 * pinned by the conformance `pseudonym` vectors.
 *
 *   pseudonym(field) = SHA3-256( frame(operation_salt) || frame(domain_tag) || frame(stable_id) )
 *
 * Each field is absorbed with an 8-byte big-endian length prefix (framing) so
 * field boundaries are unambiguous — without this, ("ab","c") and ("a","bc")
 * would collide. 32-byte output, lowercase hex.
 *
 * Hash: SHA3-256 (FIPS 202 fixed-output), not SHAKE-256. The output is a fixed
 * 32 bytes, so the XOF buys nothing and carries a domain-prefix hazard; SHA3-256
 * is the conventional fixed-length choice and aligns with CCCP/1.
 *
 * Parity is pinned by the conformance vectors at
 * `certcrypt-conformance/fixtures/primitives/pseudonym/vectors.json`.
 */

import { digestHexBytes } from "./digest.js";
import { concatBytes, utf8Bytes } from "./provider/bytes.js";

export type PseudonymDomain = "holder" | "pool" | "authorization";

/** Absorb a field with an 8-byte big-endian length prefix. */
function frame(field: Uint8Array): Uint8Array {
  const len = new Uint8Array(8);
  new DataView(len.buffer).setBigUint64(0, BigInt(field.length), false);
  return concatBytes(len, field);
}

/**
 * Derive an operation-scoped pseudonym. `operationSalt` is the public
 * per-operation salt carried in the package; `domain` separates namespaces;
 * `stableId` is the identifier being projected (it never appears in the
 * capacity evidence; only its pseudonym does).
 */
export function derivePseudonym(
  operationSalt: Uint8Array,
  domain: PseudonymDomain,
  stableId: string
): string {
  // One absorb over the concatenated framed fields — identical bytes, and
  // therefore an identical digest, to the streaming update() form.
  return digestHexBytes(
    concatBytes(
      frame(operationSalt),
      frame(utf8Bytes(domain)),
      frame(utf8Bytes(stableId))
    )
  );
}
