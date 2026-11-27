/**
 * The toolkit's public surface — identical on Node and in the browser.
 *
 * Both entry points (`verify-node.ts`, `verify-web.ts`) re-export this module, so
 * an integrator gets the same API on either runtime and code written against one
 * runs on the other.
 *
 * ## What is here, and what is not
 *
 * The rule is **complete operations, never loose primitives**. Everything below
 * is something a caller can use without being able to reach a wrong answer that
 * still looks right. Deliberately NOT exported:
 *
 *   - `computeMerkleRoot` / `computeLeafHash` / `generateInclusionProof` — the
 *     pieces of the HOLDER-KEYSET fold (`holder-keyset.merkle-sha3-256/1`).
 *     Exposing them invites hand-rolling that tree, and no public operation
 *     needs them.
 *
 * The collection fold (`collectionLeafHash` / `collectionNodeHash` /
 * `collectionMerkleRoot`) IS exported, and that is a deliberate exception.
 * Because `subject.collection/1` §7.4 places the per-leaf commitments INSIDE the
 * signed certificate, a holder of the certificate can derive an inclusion proof for any
 * element from `leaves[]` alone — no issuer round-trip, no separately delivered
 * proof file. Deriving it is not hand-rolling a tree: the inputs are signed. The
 * verdict still comes from `verifyCollectionInclusion`, which is fail-closed.
 *   - `verifyEd25519Signature` / `verifyEcdsaP256Signature` /
 *     `verifyMlDsa65Signature` — single components of a composite signature.
 *     `ecdsa-p256.ts` says it outright: a component MUST NOT be used as a
 *     signature-verdict API on its own. A composite is valid only through
 *     `verifyComposite` (the AND of all components), so only that is exported —
 *     exporting the components would be handing out a way to accept a signature
 *     whose post-quantum half was stripped.
 *   - `derivePseudonym`, the `assert*Precondition` helpers, the crypto provider
 *     internals — implementation detail with no standalone meaning.
 *
 * Nothing here can produce a signature. The toolkit evaluates artifacts under
 * public rules and holds no secrets; the crypto provider interface exposes
 * hashing and signature *verification* only.
 */

// ── The verdict ─────────────────────────────────────────────────────────────

export { verify } from "./verify.js";

// ── Element-level inclusion (verifier-toolkit/1) ─────────────────────

/**
 * Required by the spec: a conforming toolkit MUST expose an element-level
 * inclusion operation — given ONE declared leaf, its inclusion proof, and the
 * collection's declared root and cardinality, confirm membership WITHOUT the
 * rest of the collection.
 *
 * A positive result reconstructs the identical root the whole-set construction
 * computes, and is fail-closed under the failure conditions of
 * `collection.merkle-sha3-256/1`.
 */
export {
  verifyCollectionInclusion,
  collectionLeafHash,
  collectionNodeHash,
  collectionMerkleRoot,
  COLLECTION_MERKLE_SCHEME,
} from "./crypto/collection-merkle.js";
export type {
  CollectionInclusionProof,
  CollectionInclusionResult,
} from "./crypto/collection-merkle.js";

/**
 * The same question from the certificate alone (verifier-toolkit/1 §8.4.2): the
 * leaves are signed inside the certificate, so ONE leaf value is enough. The
 * certificate is verified under the Issued route first, the declared leaves
 * must fold to the declared root, every declared leaf profile is tried, and a
 * value that repeats is reported at every position it occupies.
 */
export { verifyCollectionElementFromCertificate } from "./issued/verify-collection-element.js";
export type {
  CollectionElementOutcome,
  CollectionElementMatch,
  CollectionElementResult,
  CollectionElementOptions,
} from "./issued/verify-collection-element.js";

// ── Commitment recomputation ───────────────────────────────────────

/**
 * SHA3-256, the digest under every commitment in the spec.
 *
 * This is what lets a caller compute a commitment where the material already is
 * — in a browser, over a local file — instead of sending the material anywhere.
 */
export {
  digestHexBytes,
  digestHexText,
  digestHexStream,
  digestBytes,
} from "./crypto/digest.js";

/**
 * Canonical bytes for a subject under its declared profile, and the profiles the
 * toolkit supports. Needed to build a correct verification input: the profile
 * alone defines canonicalization, and material must be delivered byte-exact
 * (no normalizing, re-encoding, or BOM-stripping by the caller).
 */
export {
  canonicalBytesForSubject,
  SUBJECT_BINARY,
  isOpaqueByteProfile,
  OPAQUE_BYTE_PROFILES,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  SUPPORTED_SUBJECT_PROFILES,
} from "./crypto/canonical-subject.js";

/**
 * JCS (RFC 8785) canonicalization — the byte form every signature in the stack
 * is computed over. Exported so a caller can reproduce a signed view exactly.
 */
export { jcsCanonicalizeBytes, jcsCanonicalizeString } from "./crypto/jcs.js";

/**
 * Strict JSON parsing: RFC 8259, and no object repeats a member name at any
 * depth. Artifacts read from a path are parsed this way. An artifact passed in
 * memory has already been parsed by the caller, and a parser that kept one of
 * two duplicates has already lost them; parse such artifacts with this function
 * so a duplicate fails closed instead of being evaluated.
 */
export { strictJsonParse, StrictJsonError } from "./input/strict-json.js";

// ── Consistency (CCVP/1, optional plane) ────────────────────────────────────

/**
 * Consistency of a certificate with the declared context it names, under
 * CCVP/1 — an OPTIONAL plane reported beside the verdict, never part of it.
 *
 * Takes the target certificate and the candidate context snapshot certificates
 * themselves. Each one is verified under the Issued route; each snapshot's
 * issuer is derived from its signature (`signer.id` plus the composite key
 * fingerprint), never from a field it carries. No outcome changes what
 * `verify()` returns, and `consistency-match` is not endorsement, trust or a
 * step toward Independent: it says the issuance aligned with one declared
 * context, and nothing else.
 */
export { verifyConsistency } from "./consistency/verify-consistency.js";
export type {
  ConsistencyOutcome,
  ConsistencyResult,
  ConsistencyNamespace,
  SelectedSnapshot,
} from "./consistency/verify-consistency.js";

// ── Composite signatures ────────────────────────────────────────────────────

/**
 * Composite signature verification — the AND of every declared component.
 *
 * This is the ONLY signature entry point exported, by design: a composite is
 * valid only when all its components verify, so a caller cannot accidentally
 * accept one whose post-quantum component was stripped or corrupted.
 */
export {
  verifyComposite,
  compositeMPrime,
  COMPOSITE_DOMAIN_PREFIX,
  PROFILE_P256_MLDSA65,
  PROFILE_ED25519_MLDSA65,
  ALG_ECDSA_P256,
  ALG_ED25519,
  ALG_MLDSA65,
} from "./crypto/composite.js";
export type {
  ComponentSignature,
  CompositeSignatureWire,
  CompositePublicKeys,
  CompositeVerifyResult,
} from "./crypto/composite.js";

// ── System-domain configuration ─────────────────────────────────────────────

/**
 * The production profile, and the ONLY one this package exports.
 *
 * Its `system_root_fingerprint`, issuance and settlement account are the
 * published XRPL mainnet values of `rules/2026-01`, and its corpus commitment
 * for `rules/2026-01` is the `subtree_root` of the corpus proof that certifies
 * that rules text. A rules version whose corpus proof is pending carries
 * `<pending-corpus-proof>` instead, and the rules check rejects it, so
 * production verification fails closed BY DESIGN for it. Writing a concrete
 * value before its source exists is a fail-OPEN bug, not a fix.
 *
 * WHY THE TEST PROFILES ARE NOT EXPORTED
 *
 * `getEnvConfig` and `getConformanceConfig` live in `harness/`, which the
 * test suite and the conformance runner import directly and which the published
 * package does not contain (the CLI takes a profile as a file, `--test-config`,
 * instead). That is a product boundary rather than a safety measure.
 *
 * Safety is not the reason: `production_verification` already reports which
 * regime produced a result, and it compares the ENTIRE config against the
 * published profile, so a test verdict cannot be relabelled as production. The
 * reason is scope. These helpers exist to drive a test harness, and once a
 * function is in the public API someone integrates with it — after which
 * withdrawing it stops being housekeeping and starts being a breaking change.
 *
 * Verifying against a test network is a sandbox concern, outside this package's
 * scope. Adding them later is easy; removing them after someone depends on them
 * is not.
 */
export { getCertcryptConfig } from "./config/default.js";

/**
 * The digest a registry entry pins as `foundation_payload_digest`:
 * SHA3-256(JCS(unsigned statement payload)) of a `system-foundation/1`
 * statement (its Section 9). For a deployment that configures its own bootstrap
 * statement; `verify()` computes and compares it itself.
 */
export { foundationPayloadDigest } from "./foundation/verify-foundation.js";

/**
 * Rules-text authenticity (`rules-domain/1` §13.3): whether a set of documents is
 * the exact ruleset a corpus proof certifies, and whether that proof is the one
 * this configuration carries. Says nothing about whether the rules are right.
 */
export { verifyCertifiedFiles, verifyRulesCorpus } from "./rules/verify-corpus.js";
export type { CertifiedFile, CertifiedFilesResult } from "./rules/verify-corpus.js";
export type { RulesCorpusDocument, RulesCorpusResult } from "./rules/verify-corpus.js";

// ── Conformance attestation ─────────────────────────────────────────────────

/**
 * Which conformance vectors THIS build passed.
 *
 * The toolkit's own version (from `package.json`) says which code ran;
 * `CONFORMANCE_VECTORS_VERSION` says what that code was held to. A report that
 * offers reproducibility needs both, and neither substitutes for the other.
 *
 * `null` means the suite has not been run against this build — a local build
 * without the conformance checkout, or a build whose suite failed. Callers MUST
 * render nothing in that case. Reading the `VERSION` of a conformance checkout
 * directly and displaying it instead would republish a number the displaying
 * code never verified, which is the claim this constant exists to make honest.
 */
export {
  CONFORMANCE_VECTORS_VERSION,
  CONFORMANCE_FIXTURES_PASSED,
} from "./conformance/attestation.js";

// ── Post-quantum runtime ────────────────────────────────────────────────────

/**
 * Initialize the ML-DSA-65 backend. NOT optional to a verdict: ML-DSA-65 is the
 * post-quantum floor of every composite signature, so until this has resolved
 * successfully every verification returns UNSUPPORTED rather than a verdict.
 * Call once at startup.
 */
export { initMlDsa65 } from "./crypto/ml-dsa.js";

// ── Types ───────────────────────────────────────────────────────────────────

export * from "./types/index.js";
