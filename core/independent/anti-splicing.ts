import type {
  IndependenceProof,
  BaseCertificate,
  SettlementMaterial,
} from "../types/index.js";
import type { CommitmentInclusionProof } from "../types/settlement-material.js";
import { ResultBuilder } from "../result/builder.js";

/**
 * Verify anti-splicing constraints.
 *
 * Reads normative certificate fields from the signed payload.
 *
 * Leaf=subtree model: the cert carries no leaf-bound value to cross.
 * Anti-splicing instead requires the verified
 * commitment's `commitment_id` to be among the proof's `consumed_commitment_ids`
 * — the same commitment the hybrid binding included against `subtree_root` must
 * be one the proof declares it consumed. The inclusion-path verification itself
 * lives in LEAF_BINDING_VALID; this is the membership cross-check.
 */
export function verifyAntiSplicing(
  proof: IndependenceProof,
  baseCert: BaseCertificate,
  material: SettlementMaterial | null,
  commitmentInclusionProof: CommitmentInclusionProof | null,
  builder: ResultBuilder
): void {
  const mismatches: string[] = [];
  const certPayload = baseCert.payload;

  // commitment_id must be a declared consumed commitment.
  const cid = commitmentInclusionProof?.commitment_id;
  const consumed = proof.consumed_commitment_ids;
  if (!cid || !commitmentInclusionProof) {
    mismatches.push(
      "commitment inclusion proof absent under the subtree_root model"
    );
  } else if (!Array.isArray(consumed) || !consumed.includes(cid)) {
    mismatches.push(
      `commitment_id="${cid}" is not among proof.consumed_commitment_ids`
    );
  }

  // Cross-check system_id
  if (
    certPayload?.system_id &&
    certPayload.system_id !== proof.system_id
  ) {
    mismatches.push(
      `system_id: payload="${certPayload.system_id}" vs proof="${proof.system_id}"`
    );
  }

  // Cross-check rules_version
  if (
    certPayload?.rules_version &&
    certPayload.rules_version !== proof.rules_version
  ) {
    mismatches.push(
      `rules_version: payload="${certPayload.rules_version}" vs proof="${proof.rules_version}"`
    );
  }

  // Cross-check with settlement material coherence
  if (material?.coherence_material) {
    const cm = material.coherence_material;
    if (cm.system_id !== proof.system_id) {
      mismatches.push(
        `coherence.system_id: material="${cm.system_id}" vs proof="${proof.system_id}"`
      );
    }
    if (cm.rules_version !== proof.rules_version) {
      mismatches.push(
        `coherence.rules_version: material="${cm.rules_version}" vs proof="${proof.rules_version}"`
      );
    }
    if (cm.settlement_profile_id !== proof.settlement.profile_id) {
      mismatches.push(
        `coherence.settlement_profile_id: material="${cm.settlement_profile_id}" vs proof="${proof.settlement.profile_id}"`
      );
    }
  }

  if (mismatches.length > 0) {
    builder.fail(
      "ANTI_SPLICING_VALID",
      "INDEPENDENT_INVALID",
      `Anti-splicing failure: ${mismatches.join("; ")}`
    );
    return;
  }

  builder.pass("ANTI_SPLICING_VALID");
}
