import type { IndependenceProof, BaseCertificate } from "../types/index.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import type { CommitmentInclusionProof } from "../types/settlement-material.js";
import { ResultBuilder } from "../result/builder.js";
import { digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { canonicalJsonBytes } from "../crypto/canonical-json.js";
import { computeLeafHash, verifyInclusionProof } from "../crypto/merkle.js";

const COMMITMENT_LEAF_VERSION = "ccab1-commit";

function sha3_256_hex(bytes: Uint8Array): string {
  return digestHexBytes(bytes);
}

/**
 * Verify the emission binding between the base certificate and the `independence_proof`.
 *
 * Check: LEAF_BINDING_VALID
 *
 * Hybrid (leaf=subtree) binding: the cert carries no leaf-bound value to
 * equate. The binding is two chained steps:
 *   1. `SHA3-256(JCS(base_certificate)) === certificate_commitment_digest`,
 *      where the digest lives inside the zero-data capacity evidence's projected
 *      commitment. ("The cert I hold is the one this commitment backs.")
 *   2. the per-commitment inclusion proof verifies `commitment_id →
 *      subtree_root`, where `subtree_root` is the value the proof anchors.
 *      ("That commitment was accepted into the leaf the proof anchors.")
 */
const HEX64 = /^[0-9a-f]{64}$/;
const CANONICAL_UINT = /^(0|[1-9][0-9]*)$/;
const INCLUSION_MEMBERS = [
  "commitment_id",
  "commitment_leaf_hash",
  "commitment_index",
  "commitment_siblings",
  "subtree_size",
];

function commitmentInclusionProofShapeError(cip: unknown): string | null {
  if (typeof cip !== "object" || cip === null || Array.isArray(cip)) return "not a JSON object";
  const o = cip as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length !== INCLUSION_MEMBERS.length || !INCLUSION_MEMBERS.every((k) => k in o)) {
    return `must carry exactly {${INCLUSION_MEMBERS.join(", ")}}`;
  }
  if (typeof o.commitment_id !== "string" || !HEX64.test(o.commitment_id)) {
    return "commitment_id is not 64 lowercase hex";
  }
  if (typeof o.commitment_leaf_hash !== "string" || !HEX64.test(o.commitment_leaf_hash)) {
    return "commitment_leaf_hash is not 64 lowercase hex";
  }
  if (
    !Array.isArray(o.commitment_siblings) ||
    !o.commitment_siblings.every((h) => typeof h === "string" && HEX64.test(h))
  ) {
    return "commitment_siblings is not an array of 64 lowercase hex";
  }
  if (typeof o.commitment_index !== "string" || !CANONICAL_UINT.test(o.commitment_index)) {
    return "commitment_index is not a canonical unsigned integer string";
  }
  if (
    typeof o.subtree_size !== "string" ||
    !CANONICAL_UINT.test(o.subtree_size) ||
    o.subtree_size === "0"
  ) {
    return "subtree_size is not a canonical positive integer string";
  }
  if (BigInt(o.commitment_index) >= BigInt(o.subtree_size)) {
    return "commitment_index is not below subtree_size";
  }
  return null;
}

export function verifyLeafBinding(
  proof: IndependenceProof,
  baseCert: BaseCertificate,
  capacityEvidence: CapacityEvidence | null,
  commitmentInclusionProof: CommitmentInclusionProof | null,
  builder: ResultBuilder
): void {
  // Both artifacts are required for the hybrid binding — fail-closed if absent.
  if (!capacityEvidence) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INCOMPLETE",
      "proof anchors a subtree_root but no capacity evidence was supplied to bind the certificate"
    );
    builder.addMissingArtifact("capacity_evidence");
    return;
  }
  if (!commitmentInclusionProof) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INCOMPLETE",
      "proof anchors a subtree_root but no commitment inclusion proof was supplied"
    );
    builder.addMissingArtifact("commitment_inclusion_proof");
    return;
  }

  // Step 1: the cert I hold is the one this commitment backs.
  const certDigest = sha3_256_hex(jcsCanonicalizeBytes(baseCert));
  const boundDigest =
    capacityEvidence.projected_commitment.certificate_commitment_digest;
  if (certDigest !== boundDigest) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `certificate_commitment_digest mismatch: SHA3(cert)="${certDigest}" vs evidence="${boundDigest}"`
    );
    return;
  }

  // Step 2: that commitment was accepted into the leaf the proof anchors.
  const cip = commitmentInclusionProof;

  // The inclusion proof is a closed object of five members
  // (verification-package/1 §9.4.1): hashes as 64 lowercase hex, index and size
  // as canonical unsigned integers with index < size. Anything else is a
  // malformed artifact, refused before it is folded.
  const shapeError = commitmentInclusionProofShapeError(cip);
  if (shapeError) {
    builder.fail("LEAF_BINDING_VALID", "REJECTED", `commitment_inclusion_proof: ${shapeError}`);
    return;
  }

  // 2.0. Tie the supplied evidence to the commitment_id that includes into the
  //      tree. In the zero-data profile the commitment_id IS the canonical digest
  //      of the capacity evidence (capacity.evidence/1: commitment_id = the
  //      evidence digest). Without this the two
  //      binding paths only meet in the air: capacity-binding ties the evidence to
  //      the proof's digest, the inclusion path ties commitment_id to subtree_root,
  //      but nothing ties the supplied evidence to that commitment_id — a different
  //      (still self-consistent) evidence could be spliced in. RFC 8785 JCS, the
  //      same bytes the producer digests (capacity.evidence/1).
  const evidenceDigest = sha3_256_hex(jcsCanonicalizeBytes(capacityEvidence));
  if (evidenceDigest !== cip.commitment_id) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `capacity evidence does not recompute to the commitment_id it includes against: ` +
        `SHA3(evidence)="${evidenceDigest}" vs commitment_id="${cip.commitment_id}"`
    );
    return;
  }

  // 2a. The commitment leaf hash must be SHA3-256(0x00 || ordered_json({v, commitment_id})),
  //     so the verifier cannot be handed an arbitrary leaf hash.
  const expectedLeafHash = computeLeafHash(
    canonicalJsonBytes([
      ["v", COMMITMENT_LEAF_VERSION],
      ["commitment_id", cip.commitment_id],
    ])
  );
  if (cip.commitment_leaf_hash !== expectedLeafHash) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `commitment leaf hash mismatch: computed="${expectedLeafHash}" vs declared="${cip.commitment_leaf_hash}"`
    );
    return;
  }

  // 2b. The leaf hash must include against the subtree_root the proof anchors.
  const commitmentIndex = parseInt(cip.commitment_index, 10);
  const subtreeSize = parseInt(cip.subtree_size, 10);
  if (
    isNaN(commitmentIndex) ||
    isNaN(subtreeSize) ||
    commitmentIndex < 0 ||
    subtreeSize <= 0
  ) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "REJECTED",
      `invalid commitment_index=${cip.commitment_index} or subtree_size=${cip.subtree_size}`
    );
    return;
  }
  const included = verifyInclusionProof(
    cip.commitment_leaf_hash,
    commitmentIndex,
    cip.commitment_siblings,
    proof.subtree_root!,
    subtreeSize
  );
  if (!included) {
    builder.fail(
      "LEAF_BINDING_VALID",
      "INDEPENDENT_INVALID",
      "commitment inclusion proof does not verify against proof.subtree_root"
    );
    return;
  }

  builder.pass("LEAF_BINDING_VALID");
}
