/**
 * Fixed P-256 test key material for conformance fixtures.
 *
 * This is the classical (ECDSA P-256) component of the composite test root
 * (CERTCRYPT Composite Signature Profile, canonical profile certcrypt-composite-p256-mldsa65-v1) — and, under the
 * k-of-n quorum model, the classical component of root quorum MEMBER m0 (the
 * emission-certificate issuer signs as m0, system-manifest/1). The ML-DSA-65
 * component and members m1..m{n-1} are held by the generator. The test domain's
 * root id is the bootstrap manifest digest TEST_ROOT_FINGERPRINT below.
 *
 * These keys are used ONLY for test-fixture generation and conformance testing.
 * They are NOT the CERTCRYPT production root keys.
 * They MUST NOT be used for any public conformance claim.
 */

/** SEC1 uncompressed P-256 public key (65 bytes), base64. Member m0 classical component. */
export const TEST_ROOT_PUBLIC_KEY_B64 =
  "BFoVha3bUD9bFvwY30YvIYS61baB6xelloomRjlX7GvQzMAHwoV5bX+BfjnQal65oYcSxee6z78g3jwAamQ5nWA=";

/**
 * System root fingerprint = SHA3-256(JCS(system_manifest)) (system-manifest/1
 * over the bootstrap manifest version (sequence 0, one entry, k=2-of-n=3
 * composite quorum). The test domain's root id under the k-of-n quorum model.
 * Must equal the generator's digest_hex_bytes(jcs_canonicalize_bytes(
 * build_bootstrap_manifest())) for the same members.
 */
export const TEST_ROOT_FINGERPRINT =
  "4641cb3850fdfde06875bed9382b2afeb2a108ac48ef32d4e196d456a0059635";

/**
 * SHA3-256(JCS(unsigned statement payload)) of the conformance bootstrap
 * statement (system-foundation/1 §9) — the generator's
 * build_foundation_payload_digest() over the test foundation every positive
 * fixture carries.
 */
export const TEST_FOUNDATION_PAYLOAD_DIGEST =
  "5bf125fdf89aa617ab4a28fe115d8cf5850bff5aba752544eac56b9edfc9e58b";

/**
 * Synthetic corpus commitment for the test profiles.
 *
 * The conformance rules domain publishes no corpus, so no real corpus
 * proof certifies one. This value is deliberately not a plausible `subtree_root`:
 * it must never match the production commitment, so a test profile can never be
 * mistaken for a production one by the guard in core/verify.ts.
 */
export const TEST_CORPUS_ROOT =
  "0000000000000000000000000000000000000000000000000000000000000000";
