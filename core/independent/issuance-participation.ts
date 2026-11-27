import type {
  IndependenceProof,
  BaseCertificate,
  SystemDomainConfig,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";

/**
 * Verify issuance-time participation.
 *
 * Check: ISSUANCE_PARTICIPATION_VALID
 *
 * Per independence.proof/1 section 11.9:
 * - payload.anchor.root_id must be present and non-empty
 * - payload.anchor.root_id must equal proof.system_root_fingerprint
 * - No post-hoc repair permitted
 */
export function verifyIssuanceParticipation(
  proof: IndependenceProof,
  baseCert: BaseCertificate,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  const rootId = baseCert.payload?.anchor?.root_id;

  if (!rootId || rootId.length === 0) {
    builder.fail(
      "ISSUANCE_PARTICIPATION_VALID",
      "INDEPENDENT_INVALID",
      "base_certificate.payload.anchor.root_id is missing or empty — " +
        "issuance-time participation cannot be established"
    );
    return;
  }

  if (rootId !== proof.system_root_fingerprint) {
    builder.fail(
      "ISSUANCE_PARTICIPATION_VALID",
      "INDEPENDENT_INVALID",
      `payload.anchor.root_id="${rootId}" does not match proof.system_root_fingerprint="${proof.system_root_fingerprint}"`
    );
    return;
  }

  builder.pass("ISSUANCE_PARTICIPATION_VALID");
}
