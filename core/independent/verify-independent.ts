import type { LoadedArtifacts, SystemDomainConfig } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { verifyProofStructure } from "./proof-structure.js";
import { verifySystemDomain } from "../domain/verify-domain.js";
import { verifyRulesDomain } from "../rules/verify-rules.js";
import { verifyLeafBinding } from "./leaf-binding.js";
import { verifySettlement } from "./settlement.js";
import { verifyIssuanceParticipation } from "./issuance-participation.js";
import { verifyProofSignature } from "./verify-proof-signature.js";
import { verifyAntiReplay } from "./anti-replay.js";
import { verifyAntiSplicing } from "./anti-splicing.js";
import { verifyCapacityBinding } from "./capacity-binding.js";
import { verifyEffectiveUnitsBinding } from "./effective-units.js";
import { capacityEvidenceShapeError } from "./capacity-evidence.js";

/**
 * Verify the Independent path.
 *
 * Per verifier-toolkit/1 section 11.2:
 * This runs AFTER verifyIssued has already been called (step 3).
 *
 * Validation sequence (verifier-toolkit/1 §11.2; independence.proof/1 §12):
 * 1. Proof structure
 * 2. System domain attribution
 * 3. Rules domain selection
 * 4. Leaf binding
 * 5. Capacity-evidence binding — before settlement, as independence.proof/1
 *    §9 and §12.5 require: the settlement fixes a consumption whose
 *    authorization must first be shown legitimate
 * 6. Settlement (ref, finality, capacity, inclusion, aggregated interpretation)
 * 7. Issuance-time participation
 * 8. Proof signature (mandatory; authenticates the signed view, node
 *    attestation included)
 * 9. Anti-replay
 * 10. Anti-splicing
 * 11. Effective-units binding
 *
 * Short-circuit only on Independent-specific failures (via checkpoint),
 * NOT on prior Issued failures like UNSUPPORTED for signature verification.
 * This ensures the full Independent baseline runs and populates diagnostics
 * even when Issued checks have a non-blocking failure.
 */
export function verifyIndependent(
  artifacts: LoadedArtifacts,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  const baseCert = artifacts.baseCertificate!;

  // Create checkpoint after Issued phase so we only short-circuit
  // on failures from Independent checks, not from Issued UNSUPPORTED
  const cp = builder.checkpoint();

  // 1. Proof structure
  const proof = artifacts.independenceProof;
  if (!verifyProofStructure(proof, builder)) {
    builder.markEarlyExit();
    return;
  }

  // Populate structural lineage from proof (visible in result regardless of outcome)
  builder.setLineage({
    settlement_profile_id: proof.settlement?.profile_id,
    subtree_root: proof.subtree_root,
    settlement_ref: proof.settlement_ref,
    batch_root: proof.batch?.root,
    batch_index: proof.batch?.index,
    batch_size: proof.batch?.size,
  });

  // 2. System domain
  verifySystemDomain(proof, config, builder);
  if (builder.hasFailureSince(cp)) return;

  // 3. Rules domain
  verifyRulesDomain(proof, baseCert, config, builder);
  if (builder.hasFailureSince(cp)) return;

  // capacity.evidence/1 is a closed runtime artifact, not merely a TypeScript
  // interface. Validate it before any binding check dereferences its members.
  if (artifacts.capacityEvidence) {
    const shapeError = capacityEvidenceShapeError(artifacts.capacityEvidence);
    if (shapeError) {
      builder.fail(
        "CAPACITY_EVIDENCE_VALID",
        "INDEPENDENT_INVALID",
        `capacity evidence does not verify: ${shapeError}`
      );
      return;
    }
  }

  // 4. Leaf binding (hybrid leaf=subtree binding: the certificate digest in the
  //    capacity evidence, then commitment inclusion into subtree_root)
  verifyLeafBinding(
    proof,
    baseCert,
    artifacts.capacityEvidence,
    artifacts.commitmentInclusionProof,
    builder
  );
  if (builder.hasFailureSince(cp)) return;

  // 5. Capacity-evidence binding: verifies the zero-data capacity evidence and
  //    requires it to recompute to the evaluated certificate's commitment_id.
  //    Runs before settlement (independence.proof/1 §9, §12.5).
  verifyCapacityBinding(
    proof,
    artifacts.capacityEvidence,
    artifacts.commitmentInclusionProof,
    artifacts.systemFoundation,
    builder,
    config.signature_profile
  );
  if (builder.hasFailureSince(cp)) return;

  // 6. Settlement
  verifySettlement(proof, artifacts.settlementMaterial, artifacts.capacityEvidence, config, builder);
  if (builder.hasFailureSince(cp)) return;

  // 7. Issuance-time participation
  verifyIssuanceParticipation(proof, baseCert, config, builder);
  if (builder.hasFailureSince(cp)) return;

  // 8. Proof signature: the system domain's composite signature over the
  //    signed view, against the Level-1 capacity key from the foundation.
  //    Mandatory; fails closed when absent, unresolvable or invalid. Once it
  //    verifies, the node attestation it covers is authentic and is recorded
  //    for the result (reported only on INDEPENDENT_VALID).
  verifyProofSignature(proof, artifacts.systemFoundation, builder, config.signature_profile);
  if (builder.hasFailureSince(cp)) return;
  builder.setAttestedNode(proof.node_attestation ?? null);

  // 9. Anti-replay
  verifyAntiReplay(proof, builder);
  if (builder.hasFailureSince(cp)) return;

  // 10. Anti-splicing
  verifyAntiSplicing(
    proof,
    baseCert,
    artifacts.settlementMaterial,
    artifacts.commitmentInclusionProof,
    builder
  );
  if (builder.hasFailureSince(cp)) return;

  // 11. Effective-units binding: binds declared effective units to the
  //     certified subjects; under-declaration is rejected. Binds
  //     declared_effective_units to the subjects actually certified in the
  //     base-certificate anchor: capacity.commitment/1 requires it to
  //     EQUAL Σ per-subject units (collection → declared_cardinality, any other
  //     subject → 1). The only actor holding both the subjects and the declared
  //     units is this offline verifier. Fail-closed (INDEPENDENT_INVALID) on an
  //     under-declaration.
  verifyEffectiveUnitsBinding(
    baseCert,
    artifacts.capacityEvidence,
    artifacts.originalMaterial,
    builder
  );
}
