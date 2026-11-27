/**
 * Capacity-evidence binding check — the verifier step that ties the zero-data
 * capacity evidence to the exact commitment the proof consumed.
 *
 * In the zero-data profile a commitment's id IS its capacity-evidence digest
 * (`capacity.evidence/1`): the proof lists the consumed commitments by
 * those digests in `consumed_commitment_ids`, and each verified certificate
 * binds to one of them through its inclusion path (`independence.proof/1
 * 10`). So the evidence supplied for the evaluated certificate MUST recompute
 * to the `commitment_id` carried in that certificate's inclusion path — that is
 * the per-commitment binding, and it scales to a leaf of N commitments where a
 * single proof-level digest could not.
 *
 * Fail-closed: the evidence is verified offline (Level-1 anchor, holder
 * signature, pseudonyms) AND its recomputed digest is required to equal that
 * `commitment_id`. The Level-1 key comes from the system-foundation; without it
 * the anchor cannot be checked.
 */

import type { IndependenceProof } from "../types/proof.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import type { CommitmentInclusionProof } from "../types/settlement-material.js";
import type { SystemFoundation } from "../types/foundation.js";
import { ResultBuilder } from "../result/builder.js";
import {
  verifyCapacityEvidence,
  type CapacityVerdict,
} from "./capacity-evidence.js";

export function verifyCapacityBinding(
  proof: IndependenceProof,
  capacityEvidence: CapacityEvidence | null,
  commitmentInclusionProof: CommitmentInclusionProof | null,
  systemFoundation: SystemFoundation | null,
  builder: ResultBuilder,
  /** The composite profile the rules domain fixes for the Level-1 binding. */
  signatureProfile: string
): void {
  // The evaluated certificate's commitment_id (= its evidence digest in the
  // zero-data profile) is what the supplied evidence must recompute to.
  const boundCommitmentId = commitmentInclusionProof?.commitment_id;
  if (!boundCommitmentId) {
    builder.fail(
      "CAPACITY_EVIDENCE_VALID",
      "INCOMPLETE",
      "no commitment inclusion proof to bind the capacity evidence to"
    );
    builder.addMissingArtifact("commitment_inclusion_proof");
    return;
  }

  // No evidence to check against the commitment it must back → fail-closed.
  if (!capacityEvidence) {
    builder.fail(
      "CAPACITY_EVIDENCE_VALID",
      "INCOMPLETE",
      "proof consumes a commitment but no capacity evidence was supplied to back it"
    );
    builder.addMissingArtifact("capacity_evidence");
    return;
  }

  // Need the system-domain Level-1 COMPOSITE key (both components). The
  // capacity-evidence L1 binding signature is a PQ/T hybrid composite (CERTCRYPT Composite Signature Profile),
  // verified AND against both published component keys.
  const sdMldsa = systemFoundation?.system_domain_capacity_key_mldsa_b64;
  const sdClassical = systemFoundation?.system_domain_capacity_key_p256_b64;
  if (!sdMldsa || !sdClassical) {
    builder.fail(
      "CAPACITY_EVIDENCE_VALID",
      "INCOMPLETE",
      "capacity evidence present but no (complete composite) system-domain Level-1 key to verify its anchor"
    );
    builder.addMissingArtifact("system_foundation");
    return;
  }

  // Verify the evidence (offline anchor + holder signature + pseudonyms) AND
  // require its recomputed digest to equal the evaluated certificate's
  // commitment_id (zero-data per-commitment binding, capacity.evidence/1).
  const verdict: CapacityVerdict = verifyCapacityEvidence(
    capacityEvidence,
    sdMldsa,
    sdClassical,
    boundCommitmentId,
    signatureProfile
  );
  if (!verdict.verified) {
    builder.fail(
      "CAPACITY_EVIDENCE_VALID",
      "INDEPENDENT_INVALID",
      `capacity evidence does not verify: ${verdict.reason}`
    );
    return;
  }

  builder.pass("CAPACITY_EVIDENCE_VALID");
}
