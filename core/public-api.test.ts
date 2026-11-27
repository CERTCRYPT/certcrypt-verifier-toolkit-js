/**
 * The public surface is a contract, so it is pinned by a test rather than left
 * to whatever the entry files happen to re-export.
 *
 * Two properties matter and neither is visible by reading one file:
 *   1. Node and browser expose the SAME surface — code written against one runs
 *      on the other. A missing export on one side is a silent portability break.
 *   2. The primitives that MUST NOT be exported stay unexported. Single
 *      signature components are the dangerous case: handing one out is handing
 *      out a way to accept a composite whose post-quantum half was stripped.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import * as nodeApi from "./verify-node.js";
import * as webApi from "./verify-web.js";

/** Everything an integrator is entitled to rely on. */
const REQUIRED_EXPORTS = [
  // the verdict
  "verify",
  // element-level inclusion — verifier-toolkit/1 MUST expose
  "verifyCollectionInclusion",
  // the same from the certificate and one leaf value alone (verifier-toolkit/1 §8.4.2)
  "verifyCollectionElementFromCertificate",
  "COLLECTION_MERKLE_SCHEME",
  // commitment recomputation
  "digestHexBytes",
  "digestHexText",
  "digestBytes",
  "canonicalBytesForSubject",
  "SUBJECT_BINARY",
  "SUBJECT_TEXT",
  "SUBJECT_EMAIL",
  "SUBJECT_COLLECTION",
  "SUBJECT_AI_DECISION",
  "SUPPORTED_SUBJECT_PROFILES",
  "jcsCanonicalizeBytes",
  "jcsCanonicalizeString",
  // strict JSON: how an in-memory artifact is parsed so a duplicate fails closed
  "strictJsonParse",
  "StrictJsonError",
  // CCVP/1 consistency — an optional plane beside the verdict (verifier-toolkit/1 §11.3)
  "verifyConsistency",
  // The collection fold: exported so a certificate holder can DERIVE an inclusion
  // proof from the signed `leaves[]` (subject.collection/1 §7.4). Required, not
  // merely tolerated — a consumer relying on element-level checks depends on it.
  "collectionLeafHash",
  "collectionNodeHash",
  "collectionMerkleRoot",
  // composite signatures — the AND, never a component
  "verifyComposite",
  "compositeMPrime",
  "COMPOSITE_DOMAIN_PREFIX",
  "PROFILE_P256_MLDSA65",
  "PROFILE_ED25519_MLDSA65",
  "ALG_ECDSA_P256",
  "ALG_ED25519",
  "ALG_MLDSA65",
  // configuration — the production profile ONLY. The test profiles live in
  // harness/, outside the published package (this suite imports them directly):
  // they drive a test harness. Verifying against a test network is
  // a sandbox concern, outside this package's scope. See the note in public-api.ts.
  "getCertcryptConfig",
  "foundationPayloadDigest",
  // post-quantum backend (the ML-DSA-65 component of the composite is normative)
  "initMlDsa65",
] as const;

/**
 * Exports that would let a caller reach a wrong answer that still looks right.
 * Single signature components head the list: `ecdsa-p256.ts` states that a
 * component MUST NOT serve as a signature-verdict API on its own.
 */
const FORBIDDEN_EXPORTS = [
  "verifyEd25519Signature",
  "verifyEcdsaP256Signature",
  "verifyMlDsa65Signature",
  "computeMerkleRoot",
  "computeLeafHash",
  "generateInclusionProof",
  "verifyInclusionProof",
  "derivePseudonym",
  "getCryptoProvider",
  "setCryptoProvider",
  "nodeProvider",
  "webProvider",
] as const;

for (const [label, api] of [
  ["node", nodeApi],
  ["web", webApi],
] as const) {
  test(`${label} entry exposes the full public surface`, () => {
    for (const name of REQUIRED_EXPORTS) {
      assert.ok(
        name in api,
        `${label} entry is missing the public export "${name}"`
      );
      assert.notEqual(
        (api as Record<string, unknown>)[name],
        undefined,
        `${label} entry exports "${name}" as undefined`
      );
    }
  });

  test(`${label} entry does not leak unsafe primitives`, () => {
    for (const name of FORBIDDEN_EXPORTS) {
      assert.ok(
        !(name in api),
        `${label} entry exports "${name}", which must stay internal`
      );
    }
  });
}

test("node and web entries expose an identical surface", () => {
  const nodeNames = Object.keys(nodeApi).sort();
  const webNames = Object.keys(webApi).sort();
  assert.deepEqual(
    nodeNames,
    webNames,
    "the two entry points diverged — code written against one would not run on the other"
  );
});

test("the element-level inclusion operation is reachable and fail-closed", () => {
  // Requires the operation to exist AND to reject adversary-controlled
  // proof material rather than throwing. A garbage proof must be a false
  // verdict with a reason, on both runtimes.
  for (const [label, api] of [
    ["node", nodeApi],
    ["web", webApi],
  ] as const) {
    const result = api.verifyCollectionInclusion(
      new TextEncoder().encode("a".repeat(64)),
      "subject.binary/1",
      new Uint8Array([1, 2, 3]),
      { proof_version: "wrong/1", leaf_index: "0", sibling_hashes: [] },
      "1",
      "0".repeat(64)
    );
    assert.equal(result.valid, false, `${label}: accepted a bogus proof`);
    assert.ok(
      typeof result.reason === "string" && result.reason.length > 0,
      `${label}: rejection carried no reason`
    );
  }
});

test("no configuration can switch signature verification off", () => {
  // Every signature is verified under every profile: the config carries no
  // field that would let a present-but-unverified signature pass.
  for (const [label, api] of [
    ["node", nodeApi],
    ["web", webApi],
  ] as const) {
    assert.equal(
      "signature_verification_mode" in api.getCertcryptConfig(),
      false,
      `${label}: the production config declares a signature verification mode`
    );
  }
});
