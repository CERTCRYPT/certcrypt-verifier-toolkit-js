/**
 * The canonical views of an `independence.proof/1` artifact, shared by the
 * structural check, the signature check and the anti-replay check so the three
 * never disagree on which members a view carries.
 */

import type { AntiReplay, IndependenceProof } from "../types/index.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";

/**
 * The identity view `proof_id` digests (independence.proof/1 §10.3.1): exactly
 * these eight members.
 */
export function proofIdentityView(proof: IndependenceProof): Record<string, unknown> {
  return {
    proof_version: proof.proof_version,
    system_id: proof.system_id,
    rules_version: proof.rules_version,
    system_root_fingerprint: proof.system_root_fingerprint,
    subtree_root: proof.subtree_root,
    closure_time: proof.closure_time,
    consumed_commitment_ids: proof.consumed_commitment_ids,
    settlement_ref: proof.settlement_ref,
  };
}

/** `proof_id` = SHA3-256(UTF-8(JCS(identity view))). */
export function computeProofId(proof: IndependenceProof): string {
  return digestHexBytes(jcsCanonicalizeBytes(proofIdentityView(proof)));
}

/**
 * The signed view (independence.proof/1 §10.13.1): the identity view plus
 * `proof_id`, `anti_replay` and, only when present, `node_attestation`. An
 * absent `node_attestation` is omitted, never serialized as null.
 */
export function proofSignedView(proof: IndependenceProof): Record<string, unknown> {
  const view: Record<string, unknown> = {
    ...proofIdentityView(proof),
    proof_id: proof.proof_id,
    anti_replay: proof.anti_replay,
  };
  if (proof.node_attestation !== undefined) {
    view.node_attestation = proof.node_attestation;
  }
  return view;
}

/** `proof_digest` = SHA3-256(UTF-8(JCS(proof with proof_digest = ""))). */
export function computeProofDigest(proof: IndependenceProof): string {
  return digestHexBytes(jcsCanonicalizeBytes({ ...proof, proof_digest: "" }));
}

/**
 * The `anti_replay` derivation (independence.proof/1 §10.9): two
 * domain-separated SHA3-256 digests of `settlement_ref ":" subtree_root`.
 */
export function deriveAntiReplay(settlementRef: string, subtreeRoot: string): AntiReplay {
  return {
    nonce: digestHexText(`certcrypt/anti-replay/1/nonce:${settlementRef}:${subtreeRoot}`),
    derivation: digestHexText(
      `certcrypt/anti-replay/1/derivation:${settlementRef}:${subtreeRoot}`
    ),
  };
}
