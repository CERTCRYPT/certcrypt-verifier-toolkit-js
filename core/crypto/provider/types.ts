/**
 * The cryptographic surface the verification core depends on.
 *
 * Every primitive the toolkit needs is a VERIFICATION operation: hashing, and
 * checking a signature against a PUBLIC key. There is deliberately no signing,
 * no key generation, and no randomness in this interface — the toolkit evaluates
 * artifacts under public rules and holds no secrets, so a backend that could
 * produce a signature would be a backend that exceeds the toolkit's role.
 *
 * Two backends implement it: `node.ts` (node:crypto, the default under Node) and
 * `web.ts` (@noble, for browsers and any runtime without node:crypto). Both are
 * exercised by the same conformance vectors, so the browser path is audited
 * rather than assumed.
 */

/**
 * An in-progress SHA3-256. Single-use: `digest()` finalizes it and the instance must not be
 * updated again — mirroring what both backends enforce underneath.
 */
export interface Sha3Stream {
  update(chunk: Uint8Array): void;
  digest(): Uint8Array;
}

export interface CryptoProvider {
  /** Which backend is active — surfaced in diagnostics, never used for logic. */
  readonly backend: "node" | "web";

  /** SHA3-256 over raw bytes. */
  sha3_256(data: Uint8Array): Uint8Array;

  /**
   * An incremental SHA3-256, for material too large to hold in memory at once.
   *
   * Exists because the one-shot form forces the caller to materialize the whole input, and a
   * browser cannot: `file.arrayBuffer()` on a multi-gigabyte file dies without a catchable
   * error — the OS hands out virtual memory lazily, so neither the allocation nor the first
   * write fails, and the tab is simply killed later by memory pressure. Chunked reading plus
   * this is the only way a large file can be verified client-side at all.
   *
   * Both backends already support it: node's `createHash("sha3-256")` and noble's
   * `sha3_256.create()`, verified to produce byte-identical digests to the one-shot form.
   *
   * ONLY valid where canonical_bytes are the input bytes — i.e. `subject.binary/1`. The text,
   * email and JSON-object profiles canonicalize before hashing (line endings, header
   * unfolding, JCS), and canonicalization is not chunk-local: a CRLF or a folded header can
   * be split across a boundary, and JCS needs the parsed value. Callers must not stream those.
   */
  sha3_256_stream(): Sha3Stream;

  /**
   * Verify an Ed25519 signature.
   *
   * @param publicKey  raw 32-byte key, or SPKI DER
   * @param message    the exact bytes that were signed
   * @param signature  the 64-byte signature
   * @returns true iff the signature is valid; false on any verification failure
   * @throws only on malformed key material, never on a merely-invalid signature
   */
  verifyEd25519(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): boolean;

  /**
   * Verify an ECDSA P-256 signature, the classical component of
   * `certcrypt-composite-p256-mldsa65-v1`.
   *
   * The digest is **SHA3-256**, not SHA-2 — CERTCRYPT's stack-wide hash, and
   * ECDSA is hash-agnostic. A backend that quietly used SHA-256 here would
   * reject every valid signature.
   *
   * The backend hashes `message` itself rather than accepting a digest: node's
   * prehash path (null algorithm) reduces the digest differently from the
   * reference signer and does not interoperate.
   *
   * Signature form is `raw-rs-64` (IEEE P1363 r||s). Low-s enforcement is NOT a
   * backend concern — the caller gates it before reaching here, so the rule is
   * applied identically on every runtime.
   *
   * @param publicKey  SEC1 compressed (33B) / uncompressed (65B), or SPKI DER
   * @param message    the exact message bytes that were signed
   * @param signature  64-byte r||s
   */
  verifyEcdsaP256Sha3(
    publicKey: Uint8Array,
    message: Uint8Array,
    signature: Uint8Array
  ): boolean;
}
