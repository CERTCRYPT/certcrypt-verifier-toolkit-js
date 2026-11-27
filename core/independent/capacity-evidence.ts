/**
 * Offline zero-data capacity-evidence verification (capacity.evidence/1),
 * byte-compatible with the reference producer. This lets the OFFLINE
 * verifier run the capacity proof for
 * itself (system-domain authorization + holder signature + bindings) WITHOUT
 * receiving stable identifiers.
 *
 * Fail-closed: any redaction or inconsistency fails the evidence
 * (CAPACITY_EVIDENCE_VALID, capacity.evidence/1 §10); never a partial pass. Parity with the reference producer is pinned by the conformance
 * primitive vectors.
 *
 * The authorization window is checked here; expiry against the settlement and
 * single consumption depend on the settlement material (out of scope here).
 */

import { verifyOperationKeyDisclosure } from "../crypto/holder-keyset.js";
import { verifyMlDsa65Signature } from "../crypto/ml-dsa.js";
import { verifyComposite } from "../crypto/composite.js";
import { digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import {
  type CapacityEvidence,
  ZERO_DATA_PROFILE,
  projectedCommitmentSigningBytes,
  level1BindingSigningBytes,
} from "../types/capacity-evidence.js";

/** The role a capacity holder authorization grants (capacity.holder-authorization/1 §7). */
const AUTHORIZED_ROLE = "capacity_commitment_holder";
const LOWER_HEX_BYTES = /^(?:[0-9a-f]{2})+$/;
const COMMITMENT_INSTANT = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

const EVIDENCE_MEMBERS = [
  "profile", "operation_salt_hex", "projected_authorization",
  "projected_commitment", "operation_key", "commitment_signature_b64",
] as const;
const AUTHORIZATION_MEMBERS = [
  "system_id", "rules_version", "system_root_fingerprint", "authorized_role",
  "authorization_issuer_kid", "valid_from", "valid_until", "holder_key_set_root",
  "level1_binding", "level1_signature", "authorization_pseudonym", "holder_pseudonym",
] as const;
const BINDING_MEMBERS = [
  "system_id", "rules_version", "system_root_fingerprint", "authorized_role",
  "authorization_issuer_kid", "valid_from", "valid_until", "holder_key_set_root",
] as const;
const COMMITMENT_MEMBERS = [
  "commitment_version", "system_id", "system_root_fingerprint", "rules_version",
  "authorization_pseudonym", "holder_pseudonym", "pool_pseudonym",
  "certificate_commitment_digest", "consumed_quantity", "declared_effective_units",
  "issued_at", "expires_at",
] as const;
const OPERATION_KEY_MEMBERS = [
  "leaf_index", "public_key_b64", "inclusion_proof", "tree_size",
] as const;

function exactRecord(
  value: unknown,
  members: readonly string[],
  label: string
): { record?: Record<string, unknown>; error?: string } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return { error: `${label} is not a JSON object` };
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== members.length || !members.every((member) => member in record)) {
    return { error: `${label} must carry exactly {${members.join(", ")}}` };
  }
  return { record };
}

function stringMemberError(
  record: Record<string, unknown>,
  members: readonly string[],
  label: string
): string | null {
  const wrong = members.find((member) => typeof record[member] !== "string");
  return wrong ? `${label}.${wrong} is not a string` : null;
}

/** Closed runtime shape required by capacity.evidence/1 Sections 4 to 6. */
export function capacityEvidenceShapeError(evidence: unknown): string | null {
  const top = exactRecord(evidence, EVIDENCE_MEMBERS, "capacity_evidence");
  if (top.error) return top.error;
  const e = top.record!;
  const topStrings = stringMemberError(
    e,
    ["profile", "operation_salt_hex", "commitment_signature_b64"],
    "capacity_evidence"
  );
  if (topStrings) return topStrings;
  if (!LOWER_HEX_BYTES.test(e.operation_salt_hex as string)) {
    return "capacity_evidence.operation_salt_hex is not lowercase hexadecimal bytes";
  }

  const projectedAuthorization = exactRecord(
    e.projected_authorization,
    AUTHORIZATION_MEMBERS,
    "capacity_evidence.projected_authorization"
  );
  if (projectedAuthorization.error) return projectedAuthorization.error;
  const auth = projectedAuthorization.record!;
  const authStrings = stringMemberError(
    auth,
    AUTHORIZATION_MEMBERS.filter(
      (member) => member !== "level1_binding" && member !== "level1_signature"
    ),
    "capacity_evidence.projected_authorization"
  );
  if (authStrings) return authStrings;

  const binding = exactRecord(
    auth.level1_binding,
    BINDING_MEMBERS,
    "capacity_evidence.projected_authorization.level1_binding"
  );
  if (binding.error) return binding.error;
  const bindingStrings = stringMemberError(
    binding.record!,
    BINDING_MEMBERS,
    "capacity_evidence.projected_authorization.level1_binding"
  );
  if (bindingStrings) return bindingStrings;
  if (
    typeof auth.level1_signature !== "object" ||
    auth.level1_signature === null ||
    Array.isArray(auth.level1_signature)
  ) {
    return "capacity_evidence.projected_authorization.level1_signature is not a JSON object";
  }

  const projectedCommitment = exactRecord(
    e.projected_commitment,
    COMMITMENT_MEMBERS,
    "capacity_evidence.projected_commitment"
  );
  if (projectedCommitment.error) return projectedCommitment.error;
  const commitmentStrings = stringMemberError(
    projectedCommitment.record!,
    COMMITMENT_MEMBERS,
    "capacity_evidence.projected_commitment"
  );
  if (commitmentStrings) return commitmentStrings;
  for (const member of ["issued_at", "expires_at"] as const) {
    if (parseCommitmentInstant(projectedCommitment.record![member] as string) === null) {
      return `capacity_evidence.projected_commitment.${member} is not RFC 3339 UTC with whole seconds`;
    }
  }

  const operationKey = exactRecord(
    e.operation_key,
    OPERATION_KEY_MEMBERS,
    "capacity_evidence.operation_key"
  );
  if (operationKey.error) return operationKey.error;
  const key = operationKey.record!;
  if (!Number.isSafeInteger(key.leaf_index) || (key.leaf_index as number) < 0) {
    return "capacity_evidence.operation_key.leaf_index is not a non-negative safe integer";
  }
  if (!Number.isSafeInteger(key.tree_size) || (key.tree_size as number) <= 0) {
    return "capacity_evidence.operation_key.tree_size is not a positive safe integer";
  }
  if (typeof key.public_key_b64 !== "string") {
    return "capacity_evidence.operation_key.public_key_b64 is not a string";
  }
  if (
    !Array.isArray(key.inclusion_proof) ||
    !key.inclusion_proof.every((item) => typeof item === "string")
  ) {
    return "capacity_evidence.operation_key.inclusion_proof is not an array of strings";
  }
  return null;
}

/** RFC 3339 UTC with whole seconds and a real calendar date. */
export function parseCommitmentInstant(value: string): number | null {
  const match = COMMITMENT_INSTANT.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return null;
  if (day < 1 || day > calendarDaysInMonth(year, month)) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function parseRfc3339Instant(value: string): number | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match.slice(0, 7).map(Number);
  if (month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return null;
  if (day < 1 || day > calendarDaysInMonth(year, month)) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function calendarDaysInMonth(year: number, month: number): number {
  if (month === 2) {
    const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
    return leap ? 29 : 28;
  }
  return [4, 6, 9, 11].includes(month) ? 30 : 31;
}

export type CapacityVerdict =
  | { verified: true }
  | { verified: false; reason: string };

function fail(reason: string): CapacityVerdict {
  return { verified: false, reason };
}

function sha3_256_hex(bytes: Uint8Array): string {
  return digestHexBytes(bytes);
}

/**
 * Verify zero-data capacity evidence offline.
 *
 * @param evidence the capacity evidence from the `verification_package`
 * @param systemDomainPublicKeyB64 the Level-1 verification key resolved from
 *   system-manifest/1 via the evidence's authorization_issuer_kid. This makes
 *   step 2 (the trust anchor) real.
 * @param expectedEvidenceDigest the digest bound in the IndependenceProofV1;
 *   null to skip that binding check in isolation.
 */
export function verifyCapacityEvidence(
  evidence: CapacityEvidence,
  systemDomainMldsaPublicKeyB64: string,
  // Classical component pubkey of the composite L1 key, in the one encoding the
  // rules domain's signature profile fixes (a 65-byte SEC1 uncompressed P-256
  // point for the canonical profile; a raw Ed25519 key is malformed there).
  systemDomainClassicalPublicKeyB64: string,
  expectedEvidenceDigest: string | null,
  /** The composite profile the rules domain fixes for the Level-1 binding. */
  signatureProfile: string
): CapacityVerdict {
  const shapeError = capacityEvidenceShapeError(evidence);
  if (shapeError) return fail(shapeError);
  if (evidence.profile !== ZERO_DATA_PROFILE) {
    return fail(`unexpected profile: ${evidence.profile}`);
  }
  if (!LOWER_HEX_BYTES.test(evidence.operation_salt_hex)) {
    return fail("operation_salt missing or invalid");
  }

  const auth = evidence.projected_authorization;
  const com = evidence.projected_commitment;

  // Step 2 (trust anchor): verify the system-domain Level-1
  // signature over the binding, and that the binding commits to the SAME root
  // the membership check (step 3) uses.
  const binding = auth.level1_binding;
  if (binding.holder_key_set_root !== auth.holder_key_set_root) {
    return fail("level1_binding root does not match projected holder_key_set_root");
  }
  if (
    binding.system_id !== auth.system_id ||
    binding.rules_version !== auth.rules_version ||
    binding.system_root_fingerprint !== auth.system_root_fingerprint ||
    binding.authorized_role !== auth.authorized_role ||
    binding.authorization_issuer_kid !== auth.authorization_issuer_kid ||
    binding.valid_from !== auth.valid_from ||
    binding.valid_until !== auth.valid_until
  ) {
    return fail("level1_binding fields do not match projected authorization");
  }
  // The authorization grants exactly the commitment-holder role
  // (capacity.holder-authorization/1 §7 step 2; capacity.evidence/1 §8 step 3).
  if (binding.authorized_role !== AUTHORIZED_ROLE) {
    return fail(
      `authorized_role is "${binding.authorized_role}", expected "${AUTHORIZED_ROLE}"`
    );
  }
  // The commitment is signed inside the authorization's window
  // (capacity.evidence/1 §8 step 2; capacity.holder-authorization/1 §5.1): an
  // issued_at outside [valid_from, valid_until] is refused, inclusive at both
  // ends. Unparseable bounds refuse too — a window that cannot be read is not
  // one the commitment can be shown to fall in.
  const issuedAt = parseCommitmentInstant(com.issued_at);
  const expiresAt = parseCommitmentInstant(com.expires_at);
  const validFrom = parseRfc3339Instant(binding.valid_from);
  const validUntil = parseRfc3339Instant(binding.valid_until);
  if ([issuedAt, expiresAt, validFrom, validUntil].some((instant) => instant === null)) {
    return fail(
      `non-canonical commitment instant or unparseable authorization window ` +
        `(valid_from=${binding.valid_from}, valid_until=${binding.valid_until}, ` +
        `issued_at=${com.issued_at}, expires_at=${com.expires_at})`
    );
  }
  if (issuedAt! < validFrom! || issuedAt! > validUntil!) {
    return fail(
      `commitment issued_at=${com.issued_at} falls outside the authorization window ` +
        `[${binding.valid_from}, ${binding.valid_until}]`
    );
  }
  // Composite L1 anchor (CERTCRYPT Composite Signature Profile): both components sign M'(SHA3(binding signing bytes)); AND.
  // The expected profile is the rules domain's, never the one the signature declares.
  if (auth.level1_signature.alg !== signatureProfile) {
    return fail(
      `level-1 signature profile "${auth.level1_signature.alg}" is not the rules domain's "${signatureProfile}"`
    );
  }
  const bindingDigestHex = digestHexBytes(level1BindingSigningBytes(binding));
  const l1 = verifyComposite(
    signatureProfile,
    bindingDigestHex,
    auth.level1_signature,
    {
      classicalPubB64: systemDomainClassicalPublicKeyB64,
      mldsaPubB64: systemDomainMldsaPublicKeyB64,
    }
  );
  if (l1.malformed) {
    return fail(`level-1 composite signature is malformed: ${l1.malformed}`);
  }
  if (l1.mldsa.performed === false && (l1.mldsa.reason ?? "").startsWith("unsupported_runtime")) {
    return fail(`level-1 signature not verifiable: ${l1.mldsa.reason}`);
  }
  if (!l1.valid) {
    return fail(
      "level-1 composite signature does not verify against system-domain key — " +
        "holder_key_set_root is not system-domain-authorized"
    );
  }

  // Step 3: leaf key membership in the authorized operation-key root, with the
  // disclosure checked as the parsed JSON it is (holder-keyset/1 §11-§13).
  const ok = evidence.operation_key;
  const membership = verifyOperationKeyDisclosure(ok, auth.holder_key_set_root);
  if (!membership.valid) {
    return fail(`operation key not a member of holder_key_set_root: ${membership.reason}`);
  }

  // Step 4: real ML-DSA-65 verification of the projected commitment against
  // the disclosed leaf key (NOT an opaque commitment).
  const l3 = verifyMlDsa65Signature(
    ok.public_key_b64,
    projectedCommitmentSigningBytes(com),
    evidence.commitment_signature_b64
  );
  if (!l3.performed) {
    return fail(`commitment signature not verifiable: ${l3.reason}`);
  }
  if (l3.passed !== true) {
    return fail("commitment signature does not verify against operation leaf key");
  }

  // Step 5: internal pseudonym bindings (anti-splicing on pseudonyms).
  if (com.holder_pseudonym !== auth.holder_pseudonym) {
    return fail("holder pseudonym mismatch between commitment and authorization");
  }
  if (com.authorization_pseudonym !== auth.authorization_pseudonym) {
    return fail("authorization pseudonym mismatch between commitment and authorization");
  }
  if (
    com.system_id !== auth.system_id ||
    com.rules_version !== auth.rules_version ||
    com.system_root_fingerprint !== auth.system_root_fingerprint
  ) {
    return fail("system context mismatch");
  }

  // Step 6: bind evidence digest to the IndependenceProofV1 (anti-splicing).
  // RFC 8785 JCS (sorted keys), matching the reference producer's evidence
  // digest — NOT JSON.stringify, whose insertion order would diverge.
  if (expectedEvidenceDigest !== null) {
    const digest = sha3_256_hex(jcsCanonicalizeBytes(evidence));
    if (digest !== expectedEvidenceDigest) {
      return fail("capacity evidence digest does not match the digest bound in the proof");
    }
  }

  return { verified: true };
}
