import type { IndependenceProof, SystemDomainConfig } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";

/**
 * Verify system-domain attribution.
 *
 * Checks: SYSTEM_DOMAIN_EXACT, SYSTEM_ROOT_BINDING_VALID, CLONE_OR_FORK_REJECTED
 *
 * Per system-domain/1:
 * - system_id must equal the configured CERTCRYPT system identity
 * - system_root_fingerprint must match the exact published bootstrap root
 * - Bare system_id without valid root fingerprint is always rejected
 */
export function verifySystemDomain(
  proof: IndependenceProof,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  // SYSTEM_DOMAIN_EXACT
  if (!proof.system_id || proof.system_id !== config.system_id) {
    builder.fail(
      "SYSTEM_DOMAIN_EXACT",
      "INDEPENDENT_INVALID",
      `system_id mismatch: expected "${config.system_id}", got "${proof.system_id ?? "(missing)"}"`
    );
    // A proof that does not carry THIS domain's system_id is a foreign context,
    // whether it names another domain or names none at all. Both are reported as
    // the clone/fork rejection: an absent identifier is not a lesser case than a
    // wrong one, and neither is attributable to this domain.
    builder.fail(
      "CLONE_OR_FORK_REJECTED",
      "INDEPENDENT_INVALID",
      proof.system_id
        ? `Proof system_id "${proof.system_id}" does not match CERTCRYPT domain`
        : "Proof carries no system_id; it is not attributable to the CERTCRYPT domain"
    );
    return;
  }
  builder.pass("SYSTEM_DOMAIN_EXACT");
  builder.addDiagnostic(
    "info",
    `system_id=${proof.system_id}`,
    "SYSTEM_DOMAIN_EXACT"
  );

  // SYSTEM_ROOT_BINDING_VALID
  if (
    !proof.system_root_fingerprint ||
    proof.system_root_fingerprint !== config.system_root_fingerprint
  ) {
    builder.fail(
      "SYSTEM_ROOT_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `system_root_fingerprint mismatch: expected "${config.system_root_fingerprint}", got "${proof.system_root_fingerprint ?? "(missing)"}"`
    );
    // Correct system_id but wrong root → clone/fork
    builder.fail(
      "CLONE_OR_FORK_REJECTED",
      "INDEPENDENT_INVALID",
      `system_id is "certcrypt" but system_root_fingerprint does not match published root`
    );
    return;
  }
  builder.pass("SYSTEM_ROOT_BINDING_VALID");
  builder.addDiagnostic(
    "info",
    `root=${proof.system_root_fingerprint}`,
    "SYSTEM_ROOT_BINDING_VALID"
  );

  // CLONE_OR_FORK_REJECTED — passed if we reached here
  builder.pass("CLONE_OR_FORK_REJECTED");
}
