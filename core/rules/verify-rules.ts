import type {
  IndependenceProof,
  BaseCertificate,
  SystemDomainConfig,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { PENDING_CORPUS_PROOF } from "../config/default.js";

/**
 * Verify rules-domain selection.
 *
 * Check: RULES_DOMAIN_EXACT
 *
 * Per rules-domain/1:
 * - rules_version must be present and non-empty
 * - rules_version must be in supported_rules_versions
 * - Cross-check with base certificate if it declares rules_version
 * - No fallback, no fuzzy match, no compatible substitution
 */
export function verifyRulesDomain(
  proof: IndependenceProof,
  baseCert: BaseCertificate,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  if (!proof.rules_version || proof.rules_version.length === 0) {
    builder.fail(
      "RULES_DOMAIN_EXACT",
      "REJECTED",
      "rules_version is missing or empty in independence_proof"
    );
    return;
  }

  // Cross-check with base certificate — read from signed payload
  const certRulesVersion = baseCert.payload?.rules_version;
  if (
    certRulesVersion &&
    certRulesVersion !== proof.rules_version
  ) {
    builder.fail(
      "RULES_DOMAIN_EXACT",
      "REJECTED",
      `rules_version mismatch: proof="${proof.rules_version}", payload="${certRulesVersion}"`
    );
    return;
  }

  if (!config.supported_rules_versions.includes(proof.rules_version)) {
    builder.fail(
      "RULES_DOMAIN_EXACT",
      "UNSUPPORTED",
      `rules_version "${proof.rules_version}" is not supported; supported: ${config.supported_rules_versions.join(", ")}`
    );
    return;
  }

  // The rules domain is selected. Whether this verifier can be trusted to have
  // been built against its authentic text is a separate question, and this is
  // where it is answered.
  //
  // rules-domain/1 §13.3.1 requires a conforming verifier to carry the certified
  // corpus commitment of every rules domain it declares support for. The
  // parameters below are compiled in and never read from the published corpus at
  // evaluation time, so this value is what lets a third party confirm those
  // parameters are the ones the published rules text actually states — that this
  // build was not made against an altered registry entry.
  //
  // Declaring support without carrying the commitment is non-conformance, not a
  // gap to tolerate: absence MUST NOT be read as permission.
  // The pending-corpus-proof marker is a declared absence, not a commitment: a non-empty
  // string that commits to nothing. Accepting it would let a build vouch for a
  // rules text no certified corpus backs, which is a fail-open.
  const corpusCommitment = config.rules_corpus_roots?.[proof.rules_version];
  if (
    typeof corpusCommitment !== "string" ||
    corpusCommitment.length === 0 ||
    corpusCommitment === PENDING_CORPUS_PROOF
  ) {
    builder.fail(
      "RULES_CORPUS_COMMITMENT_PRESENT",
      "REJECTED",
      (corpusCommitment === PENDING_CORPUS_PROOF
        ? `the corpus commitment for rules_version "${proof.rules_version}" is ` +
          "still the pending-corpus-proof marker: its rules text has not been certified yet. A "
        : `no corpus commitment for rules_version "${proof.rules_version}". A `) +
        "conforming verifier carries the certified corpus commitment of every " +
        "rules domain it supports (rules-domain/1 §13.3.1); without it, this " +
        "build cannot be shown to have been made against the authentic rules text"
    );
    return;
  }
  builder.pass("RULES_CORPUS_COMMITMENT_PRESENT");

  builder.pass("RULES_DOMAIN_EXACT");
  builder.addDiagnostic(
    "info",
    `rules_version=${proof.rules_version}`,
    "RULES_DOMAIN_EXACT"
  );
}
