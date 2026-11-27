import type { IndependenceProof } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { computeProofDigest, computeProofId } from "./proof-views.js";

// Canonical model identifier per independence.proof/1 (dot, not dash).
const SUPPORTED_PROOF_VERSION = "independence.proof/1";
/** The only `independence_result` value `/1` defines (independence.proof/1 §10.10). */
const INDEPENDENCE_RESULT = "independent";

const REQUIRED_FIELDS: (keyof IndependenceProof)[] = [
  "proof_version",
  "system_id",
  "system_root_fingerprint",
  "rules_version",
  "proof_id",
  // The leaf-bound value under the leaf=subtree model.
  "subtree_root",
  "closure_time",
  "consumed_commitment_ids",
  "settlement_ref",
  "settlement",
  "batch",
  "inclusion_proof",
  "anti_replay",
  "independence_result",
  // The proof always travels as a standalone serialized artifact, so
  // proof_digest is mandatory (independence.proof/1 §10.11).
  "proof_digest",
  // Mandatory (independence.proof/1 §10.13). Its absence is reported by
  // PROOF_SIGNATURE_VALID, which owns the signature, not here.
];

const HEX64 = /^[0-9a-f]{64}$/;
/** RFC 3339 UTC with whole seconds, the only form the proof admits. */
const UTC_SECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** `op:` followed by 22 characters of the standard base64 alphabet. */
const NODE_ID = /^op:[A-Za-z0-9+/]{22}$/;

function isUtcSeconds(v: unknown): v is string {
  return typeof v === "string" && UTC_SECONDS.test(v) && !Number.isNaN(Date.parse(v));
}

/**
 * Verify proof presence, version, and structural completeness.
 *
 * Checks: PROOF_PRESENT, PROOF_VERSION_SUPPORTED, PROOF_STRUCTURE_VALID
 */
export function verifyProofStructure(
  proof: IndependenceProof | null,
  builder: ResultBuilder
): proof is IndependenceProof {
  // PROOF_PRESENT
  if (!proof) {
    builder.fail(
      "PROOF_PRESENT",
      "INCOMPLETE",
      "independence_proof is absent"
    );
    builder.addMissingArtifact("independence_proof");
    return false;
  }
  builder.pass("PROOF_PRESENT");

  // PROOF_VERSION_SUPPORTED
  if (proof.proof_version !== SUPPORTED_PROOF_VERSION) {
    builder.fail(
      "PROOF_VERSION_SUPPORTED",
      "UNSUPPORTED",
      `proof_version "${proof.proof_version}" is not supported; expected "${SUPPORTED_PROOF_VERSION}"`
    );
    return false;
  }
  builder.pass("PROOF_VERSION_SUPPORTED");

  // PROOF_STRUCTURE_VALID
  const missing: string[] = [];
  for (const field of REQUIRED_FIELDS) {
    const value = proof[field];
    if (value === undefined || value === null || value === "") {
      missing.push(field);
    }
  }

  // Deep structure checks
  if (proof.settlement) {
    if (!proof.settlement.profile_id) missing.push("settlement.profile_id");
    if (!proof.settlement.ref) missing.push("settlement.ref");
    if (
      !Array.isArray(proof.settlement.finality_proofs) ||
      proof.settlement.finality_proofs.length === 0
    )
      missing.push("settlement.finality_proofs");
  }
  if (proof.batch) {
    if (!proof.batch.root) missing.push("batch.root");
    if (proof.batch.index === undefined || proof.batch.index === null)
      missing.push("batch.index");
    if (!proof.batch.size) missing.push("batch.size");
  }
  if (proof.anti_replay) {
    if (!proof.anti_replay.nonce) missing.push("anti_replay.nonce");
    if (!proof.anti_replay.derivation) missing.push("anti_replay.derivation");
  }
  if (!Array.isArray(proof.inclusion_proof)) {
    missing.push("inclusion_proof (not an array)");
  }

  if (missing.length > 0) {
    builder.fail(
      "PROOF_STRUCTURE_VALID",
      "REJECTED",
      `independence_proof missing required fields: ${missing.join(", ")}`
    );
    return false;
  }

  const malformed = malformedMembers(proof);
  if (malformed.length > 0) {
    builder.fail(
      "PROOF_STRUCTURE_VALID",
      "REJECTED",
      `independence_proof has malformed members: ${malformed.join("; ")}`
    );
    return false;
  }

  // proof_id digests the identity view (independence.proof/1 §10.3.1). It is in
  // the signed view, so a proof_id the signer got wrong would still verify:
  // only recomputing it catches a proof whose id names other members.
  const recomputedId = computeProofId(proof);
  if (recomputedId !== proof.proof_id) {
    builder.fail(
      "PROOF_STRUCTURE_VALID",
      "REJECTED",
      `proof_id mismatch: recomputed="${recomputedId}" vs declared="${proof.proof_id}"`
    );
    return false;
  }

  // proof_digest (independence.proof/1 §10.11) covers every member, signature
  // included. It is the artifact's own integrity digest, not the verdict's: the
  // verdict rides the signature and the bindings.
  const recomputed = computeProofDigest(proof);
  if (recomputed !== proof.proof_digest) {
    builder.fail(
      "PROOF_STRUCTURE_VALID",
      "REJECTED",
      `proof_digest mismatch: recomputed="${recomputed}" vs declared="${proof.proof_digest}"`
    );
    return false;
  }

  builder.pass("PROOF_STRUCTURE_VALID");
  return true;
}

/** Shape rules of independence.proof/1 §10 beyond presence. */
function malformedMembers(proof: IndependenceProof): string[] {
  const out: string[] = [];
  // A fixed marker under /1 (independence.proof/1 §10.10): any other value is
  // a malformed proof, never a result to read.
  if (proof.independence_result !== INDEPENDENCE_RESULT) {
    out.push(`independence_result must be exactly "${INDEPENDENCE_RESULT}"`);
  }
  if (typeof proof.proof_id !== "string" || !HEX64.test(proof.proof_id)) {
    out.push("proof_id must be 64 lowercase hex");
  }
  if (typeof proof.settlement_ref !== "string") {
    out.push("settlement_ref must be a string");
  }
  if (!isUtcSeconds(proof.closure_time)) {
    out.push("closure_time must be RFC 3339 UTC with whole seconds (YYYY-MM-DDTHH:MM:SSZ)");
  }
  const ids = proof.consumed_commitment_ids;
  if (!Array.isArray(ids) || ids.length === 0) {
    out.push("consumed_commitment_ids must be a non-empty array");
  } else if (!ids.every((id) => typeof id === "string" && HEX64.test(id))) {
    out.push("every consumed_commitment_ids entry must be 64 lowercase hex");
  } else if (new Set(ids).size !== ids.length) {
    out.push("consumed_commitment_ids must not repeat an id");
  }
  if ("node_attestation" in proof) {
    const att = proof.node_attestation as unknown;
    const keys = att && typeof att === "object" ? Object.keys(att).sort().join(",") : "";
    if (keys !== "node_id,recognized_at") {
      out.push("node_attestation must be an object with exactly node_id and recognized_at");
    } else {
      const a = att as { node_id: unknown; recognized_at: unknown };
      if (typeof a.node_id !== "string" || !NODE_ID.test(a.node_id)) {
        out.push("node_attestation.node_id must be `op:` followed by 22 base64 characters");
      }
      if (!isUtcSeconds(a.recognized_at)) {
        out.push("node_attestation.recognized_at must be RFC 3339 UTC with whole seconds");
      } else if (
        isUtcSeconds(proof.closure_time) &&
        Date.parse(a.recognized_at) < Date.parse(proof.closure_time)
      ) {
        out.push("node_attestation.recognized_at must not precede closure_time");
      }
    }
  }
  return out;
}
