import type {
  VerificationTargetRequested,
  ResolvedTarget,
  LoadedArtifacts,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";

/**
 * Resolve the verification target (verifier-toolkit/1 §11.4).
 *
 * - "issued" → Issued
 * - "independent" → Independent (a missing proof is INCOMPLETE)
 * - "auto" → Independent when ANY artifact of the Independent route was
 *   supplied (the proof, settlement material, capacity evidence or the
 *   per-commitment inclusion proof); Issued only when none was. An input that
 *   carries Independent evidence without its proof is an incomplete
 *   Independent verification, never an Issued one: reporting ISSUED_VALID for
 *   it would read as an answer to a question the input was asking about
 *   independence.
 */
export function resolveTarget(
  requested: VerificationTargetRequested,
  artifacts: LoadedArtifacts,
  builder: ResultBuilder
): ResolvedTarget | null {
  if (requested === "issued") {
    builder.pass("TARGET_AUTO_RESOLUTION_VALID");
    return "Issued";
  }

  const independentEvidence: string[] = [];
  if (artifacts.settlementMaterial) independentEvidence.push("settlement_material");
  if (artifacts.capacityEvidence) independentEvidence.push("capacity_evidence");
  if (artifacts.commitmentInclusionProof) independentEvidence.push("commitment_inclusion_proof");

  if (requested === "auto" && !artifacts.independenceProof && independentEvidence.length === 0) {
    builder.pass("TARGET_AUTO_RESOLUTION_VALID");
    return "Issued";
  }

  if (!artifacts.independenceProof) {
    builder.setResolvedTarget("Independent");
    builder.fail(
      "TARGET_AUTO_RESOLUTION_VALID",
      "INCOMPLETE",
      requested === "independent"
        ? "Target 'independent' requested but independence_proof is absent"
        : `auto resolution: ${independentEvidence.join(", ")} supplied without ` +
            "independence_proof — an incomplete Independent verification, not an Issued one"
    );
    builder.addMissingArtifact("independence_proof");
    builder.markEarlyExit();
    return null;
  }

  builder.pass("TARGET_AUTO_RESOLUTION_VALID");
  return "Independent";
}
