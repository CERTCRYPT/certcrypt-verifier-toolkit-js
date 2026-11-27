import type { VerificationPackage } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";

/**
 * The closed member set of a `verification_package` (verification-package/1
 * §9.4, §22.1): each member, and whether it holds a JSON object or a string.
 * `base_certificate` and `verification_context` are required in every package.
 */
export const PACKAGE_MEMBERS: Readonly<Record<string, "object" | "string">> = Object.freeze({
  base_certificate: "object",
  verification_context: "object",
  independence_proof: "object",
  capacity_evidence: "object",
  commitment_inclusion_proof: "object",
  settlement_material: "object",
  settlement_reference: "string",
});

const REQUIRED_MEMBERS = ["base_certificate", "verification_context"] as const;
const CONTEXT_MEMBERS = ["rules_version", "system_id"] as const;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * PACKAGE_STRUCTURE_VALID — the package is one JSON object with exactly the
 * members verification-package/1 defines, each of the right kind.
 *
 * Any other member is REJECTED rather than ignored: the package MUST NOT carry
 * original material or other leaves (§10, §18), and a member this version does
 * not define (a `version`, a `target`, a nested `supporting_material`, a
 * `system_foundation`) is either material the verifier obtains on its own or
 * a package of a format it does not read. Reading around it would verify
 * something other than what was handed over.
 *
 * Returns false after recording the failure.
 */
export function verifyPackageStructure(pkg: unknown, builder: ResultBuilder): boolean {
  const fail = (reason: string): false => {
    builder.fail("PACKAGE_STRUCTURE_VALID", "REJECTED", reason);
    return false;
  };
  if (!isPlainObject(pkg)) return fail("verification_package is not a JSON object");

  const unknown = Object.keys(pkg).filter(
    (k) => !Object.prototype.hasOwnProperty.call(PACKAGE_MEMBERS, k)
  );
  if (unknown.length > 0) {
    return fail(
      `verification_package carries member(s) verification-package/1 does not define: ` +
        unknown.map((k) => JSON.stringify(k)).join(", ")
    );
  }
  for (const name of REQUIRED_MEMBERS) {
    if (pkg[name] === undefined) return fail(`verification_package has no ${name}`);
  }
  for (const [name, kind] of Object.entries(PACKAGE_MEMBERS)) {
    const value = pkg[name];
    if (value === undefined) continue;
    const ok = kind === "object" ? isPlainObject(value) : typeof value === "string";
    if (!ok) return fail(`verification_package.${name} must be a JSON ${kind}`);
  }

  const context = pkg.verification_context as Record<string, unknown>;
  const contextKeys = Object.keys(context);
  if (
    contextKeys.length !== CONTEXT_MEMBERS.length ||
    !CONTEXT_MEMBERS.every((k) => typeof context[k] === "string" && context[k] !== "")
  ) {
    return fail(
      "verification_package.verification_context must be exactly " +
        "{rules_version, system_id}, both non-empty strings"
    );
  }

  builder.pass("PACKAGE_STRUCTURE_VALID");
  return true;
}

/**
 * PACKAGE_CONTEXT_COHERENT — the package's own declarations agree with the
 * artifacts it carries (verification-package/1 §13): `verification_context`
 * names the system domain and rules version of the certificate and, when
 * present, of the proof; `settlement_reference` repeats the proof's
 * `settlement_ref` exactly.
 *
 * A declaration that contradicts the artifacts makes the package admit two
 * readings, and an ambiguous package is REJECTED (§22.5). Certificate fields
 * are read from the signed payload, never from unsigned top-level members.
 */
export function verifyPackageContext(pkg: VerificationPackage, builder: ResultBuilder): void {
  const mismatches: string[] = [];
  const context = pkg.verification_context;
  const payload = pkg.base_certificate.payload as Record<string, unknown> | undefined;
  const proof = pkg.independence_proof as Record<string, unknown> | undefined;

  for (const field of CONTEXT_MEMBERS) {
    const declared = context[field];
    if (payload?.[field] !== declared) {
      mismatches.push(
        `verification_context.${field}=${JSON.stringify(declared)} but the certificate names ` +
          JSON.stringify(payload?.[field] ?? null)
      );
    }
    if (proof && proof[field] !== declared) {
      mismatches.push(
        `verification_context.${field}=${JSON.stringify(declared)} but the proof names ` +
          JSON.stringify(proof[field] ?? null)
      );
    }
  }

  if (pkg.settlement_reference !== undefined) {
    if (!proof) {
      mismatches.push("settlement_reference is present but the package carries no independence_proof");
    } else if (proof.settlement_ref !== pkg.settlement_reference) {
      mismatches.push(
        `settlement_reference=${JSON.stringify(pkg.settlement_reference)} but the proof's ` +
          `settlement_ref is ${JSON.stringify(proof.settlement_ref ?? null)}`
      );
    }
  }

  if (mismatches.length > 0) {
    builder.fail(
      "PACKAGE_CONTEXT_COHERENT",
      "REJECTED",
      `Package context incoherent: ${mismatches.join("; ")}`
    );
    return;
  }
  builder.pass("PACKAGE_CONTEXT_COHERENT");
}
