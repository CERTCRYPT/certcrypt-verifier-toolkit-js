import type {
  SystemFoundation,
  SystemManifest,
  ManifestEntry,
  MemberSignature,
  SystemDomainConfig,
  SuccessorBindingPayload,
  SuccessorBindingObservationInput,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import {
  verifyComposite,
  PROFILE_P256_MLDSA65,
  MLDSA65_PUBLIC_KEY_LEN,
  P256_SEC1_UNCOMPRESSED_LEN,
} from "../crypto/composite.js";

const REQUIRED_PROFILE = "system-foundation/1";
const MANIFEST_PROFILE = "system-manifest/1";
const ROOT_FINGERPRINT_DERIVATION = "sha3-256-system-manifest-jcs-v1";

const MLDSA65_PUBKEY_LEN = MLDSA65_PUBLIC_KEY_LEN;

/** Members a statement MAY carry besides the required ones (system-foundation/1 §6). */
const OPTIONAL_FIELDS = ["publication_refs", "successor_binding_observations"];

/** `foundation_statement_id` format (system-foundation/1 §6). */
const STATEMENT_ID_RE = /^[A-Za-z0-9._\/-]{1,128}$/;

/** A non-empty printable-ASCII identifier (system-manifest/1 §7.1, §7.3). */
const ASCII_ID_RE = /^[\x21-\x7e]+$/;

const REQUIRED_FIELDS: (keyof SystemFoundation)[] = [
  "foundation_profile_id",
  "foundation_statement_id",
  "system_id",
  "system_root_fingerprint",
  "system_manifest",
  "root_fingerprint_derivation",
  "system_domain_capacity_key_p256_b64",
  "system_domain_capacity_key_mldsa_b64",
  "published_rules_versions",
  "statement_issued_at",
  "statement_signatures",
];

/**
 * SHA3-256(UTF-8(JCS(payload))) of the canonical unsigned statement payload
 * (system-foundation/1 §9): the digest the bootstrap quorum signs, and the
 * value a registry entry pins as `foundation_payload_digest`.
 */
export function foundationPayloadDigest(foundation: SystemFoundation): string {
  const payload: Record<string, unknown> = {
    foundation_profile_id: foundation.foundation_profile_id,
    foundation_statement_id: foundation.foundation_statement_id,
    system_id: foundation.system_id,
    system_root_fingerprint: foundation.system_root_fingerprint,
    system_manifest: foundation.system_manifest,
    root_fingerprint_derivation: foundation.root_fingerprint_derivation,
    system_domain_capacity_key_p256_b64: foundation.system_domain_capacity_key_p256_b64,
    system_domain_capacity_key_mldsa_b64: foundation.system_domain_capacity_key_mldsa_b64,
    published_rules_versions: foundation.published_rules_versions,
    statement_issued_at: foundation.statement_issued_at,
  };
  return digestHexBytes(jcsCanonicalizeBytes(payload));
}

/**
 * Verify a system-foundation/1 statement under the k-of-n quorum model.
 *
 * Per system-foundation/1, validation sequence:
 * 1. foundation_profile_id
 * 2. system_id
 * 3. root_fingerprint_derivation = "sha3-256-system-manifest-jcs-v1"
 * 4. embedded system_manifest is a conforming BOOTSTRAP manifest (sequence 0,
 *    one entry, 2 ≤ k ≤ n, members length n, unique member_kids, correct key
 *    byte lengths)
 * 5. recompute system_root_fingerprint = SHA3-256(JCS(system_manifest)) and
 *    compare to the carried value
 * 6. system_domain_capacity_key_{p256,mldsa}_b64 present and decode
 * 7. statement_signatures meet the bootstrap entry's quorum (≥ k distinct
 *    members each producing a verifying composite signature over the payload,
 *    system-manifest/1 counting rule)
 * 8. successor-binding observations, when supplied: each authorized by ≥ k
 *    distinct bootstrap-entry members over its system-manifest/1 §9 payload,
 *    then compared for equivocation → terminal invalidity
 * 9. publication_refs only as provenance
 *
 * `published_rules_versions` is metadata, never a gate (system-foundation/1
 * §6): the statement is produced once, so a rules version registered later is
 * absent from it by construction.
 *
 * @returns The validated system_root_fingerprint, or null if validation failed.
 */
export function verifyFoundation(
  foundation: SystemFoundation,
  config: SystemDomainConfig,
  builder: ResultBuilder
): string | null {
  builder.setFoundationLineage({
    foundation_profile_id: foundation.foundation_profile_id,
    foundation_statement_id: foundation.foundation_statement_id,
    foundation_publication_ref:
      foundation.publication_refs?.[0]?.publication_reference,
  });

  // Structural completeness
  const missing: string[] = [];
  for (const field of REQUIRED_FIELDS) {
    const value = foundation[field];
    if (value === undefined || value === null || value === "") {
      missing.push(field);
    }
  }
  if (missing.length > 0) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      `Foundation statement missing required fields: ${missing.join(", ")}`
    );
    return null;
  }
  const allowed = new Set<string>([...REQUIRED_FIELDS, ...OPTIONAL_FIELDS]);
  const extra = Object.keys(foundation).filter((k) => !allowed.has(k));
  if (extra.length > 0) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      `Foundation statement carries members system-foundation/1 does not define: ${extra.join(", ")}`
    );
    return null;
  }
  if (
    typeof foundation.foundation_statement_id !== "string" ||
    !STATEMENT_ID_RE.test(foundation.foundation_statement_id)
  ) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      "foundation_statement_id must be 1-128 characters of A-Z a-z 0-9 . _ / -"
    );
    return null;
  }
  if (
    typeof foundation.statement_issued_at !== "string" ||
    !RFC3339_UTC.test(foundation.statement_issued_at) ||
    Number.isNaN(Date.parse(foundation.statement_issued_at))
  ) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      "statement_issued_at must be an RFC 3339 UTC timestamp ending in Z"
    );
    return null;
  }

  // foundation_profile_id
  if (foundation.foundation_profile_id !== REQUIRED_PROFILE) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      `foundation_profile_id must be "${REQUIRED_PROFILE}", got "${foundation.foundation_profile_id}"`
    );
    return null;
  }
  // published_rules_versions is part of the signed payload, so its shape is
  // checked; its content is metadata and gates nothing.
  const versions: unknown = foundation.published_rules_versions;
  if (!Array.isArray(versions) || !versions.every((v) => typeof v === "string")) {
    builder.fail(
      "FOUNDATION_PROFILE_VALID",
      "REJECTED",
      "published_rules_versions must be an array of strings"
    );
    return null;
  }
  builder.pass("FOUNDATION_PROFILE_VALID");

  // system_id
  if (foundation.system_id !== config.system_id) {
    builder.fail(
      "FOUNDATION_SYSTEM_ID_VALID",
      "REJECTED",
      `Foundation system_id must be "${config.system_id}", got "${foundation.system_id}"`
    );
    return null;
  }
  builder.pass("FOUNDATION_SYSTEM_ID_VALID");

  // root_fingerprint_derivation literal
  if (foundation.root_fingerprint_derivation !== ROOT_FINGERPRINT_DERIVATION) {
    builder.fail(
      "FOUNDATION_FINGERPRINT_RECOMPUTED",
      "REJECTED",
      `root_fingerprint_derivation must be "${ROOT_FINGERPRINT_DERIVATION}", got "${foundation.root_fingerprint_derivation}"`
    );
    return null;
  }

  // embedded system_manifest is a conforming bootstrap manifest version
  const manifest = foundation.system_manifest;
  const manifestError = validateBootstrapManifest(manifest, foundation.system_id);
  if (manifestError) {
    builder.fail("FOUNDATION_FINGERPRINT_RECOMPUTED", "REJECTED", manifestError);
    return null;
  }
  const bootstrapEntry = manifest.entries[0];

  // recompute system_root_fingerprint = SHA3-256(JCS(system_manifest))
  const recomputedFingerprint = digestHexBytes(jcsCanonicalizeBytes(manifest));
  if (recomputedFingerprint !== foundation.system_root_fingerprint) {
    builder.fail(
      "FOUNDATION_FINGERPRINT_RECOMPUTED",
      "REJECTED",
      `system_root_fingerprint mismatch: recomputed="${recomputedFingerprint}", declared="${foundation.system_root_fingerprint}"`
    );
    return null;
  }
  builder.pass("FOUNDATION_FINGERPRINT_RECOMPUTED");

  // statement_signatures meet the bootstrap entry's quorum (incl. the
  // capacity-key presence/decoding, which is part of the signed payload).
  const sigValid = verifyStatementQuorum(foundation, bootstrapEntry, config, builder);
  if (!sigValid) {
    return null;
  }

  // Successor-binding observations (system-manifest/1 §12.5). Each one is
  // authenticated BEFORE it is compared: its only authority is a quorum of the
  // predecessor entry's members over the §9 payload (§12.3, §13.6). The
  // predecessor is the embedded bootstrap entry — the one manifest version this
  // statement establishes — and the bootstrap entry itself is authorized by the
  // statement quorum above, never by predecessor_signatures (§11, §13.10).
  // An observation that does not reach the quorum is not evidence of anything,
  // and an input that carries one is rejected rather than half-trusted (§12.3:
  // ambiguity in attribution or verification resolves as rejection).
  const observations = foundation.successor_binding_observations;
  if (observations !== undefined) {
    const quorumError = verifySuccessorObservations(
      observations,
      foundation.system_id,
      bootstrapEntry,
      recomputedFingerprint,
      manifest.manifest_sequence
    );
    if (quorumError) {
      builder.fail("FOUNDATION_SUCCESSOR_QUORUM_VALID", "REJECTED", quorumError);
      return null;
    }
    builder.pass("FOUNDATION_SUCCESSOR_QUORUM_VALID");

    // Equivocation: two authenticated observations under one index tuple that
    // disagree on the successor → terminal invalidity (§12.5 rules 1 and 4).
    const equivocation = detectEquivocation(observations);
    if (equivocation) {
      builder.fail(
        "FOUNDATION_EQUIVOCATION_DETECTED",
        "REJECTED",
        equivocation
      );
      return null;
    }
  }

  builder.addDiagnostic(
    "info",
    `Foundation validated: system_root_fingerprint=${recomputedFingerprint}, ` +
      `quorum=${bootstrapEntry.quorum.k}-of-${bootstrapEntry.quorum.n}, ` +
      `statement_id=${foundation.foundation_statement_id}`,
    "FOUNDATION_FINGERPRINT_RECOMPUTED"
  );

  if (foundation.publication_refs && foundation.publication_refs.length > 0) {
    builder.addDiagnostic(
      "info",
      `Foundation has ${foundation.publication_refs.length} publication_ref(s) ` +
        `(provenance only, not required for validation)`,
      "FOUNDATION_PROFILE_VALID"
    );
  }

  return recomputedFingerprint;
}

/**
 * Validate the embedded manifest is a conforming system-manifest/1 BOOTSTRAP
 * version (system-foundation/1, system-manifest/1). Returns an
 * error string, or null if valid.
 */
function validateBootstrapManifest(
  manifestInput: SystemManifest,
  statementSystemId: string
): string | null {
  const manifest = manifestInput as unknown as Record<string, unknown> & SystemManifest;
  if (!isPlainObject(manifest) || !hasExactly(manifest, MANIFEST_FIELDS)) {
    return `system_manifest must carry exactly ${MANIFEST_FIELDS.join(", ")} (system-manifest/1 §6)`;
  }
  if (manifest.manifest_profile_id !== MANIFEST_PROFILE) {
    return `system_manifest.manifest_profile_id must be "${MANIFEST_PROFILE}", got "${manifest.manifest_profile_id}"`;
  }
  if (manifest.system_id !== statementSystemId) {
    return `embedded manifest system_id ("${manifest.system_id}") differs from statement system_id ("${statementSystemId}")`;
  }
  if (manifest.manifest_sequence !== 0) {
    return `embedded manifest_sequence MUST be 0 (bootstrap); got ${manifest.manifest_sequence}`;
  }
  if (!Array.isArray(manifest.entries) || manifest.entries.length !== 1) {
    return `embedded entries MUST have length 1 (bootstrap); got ${
      Array.isArray(manifest.entries) ? manifest.entries.length : "non-array"
    }`;
  }
  const e = manifest.entries[0];
  if (!isPlainObject(e) || !hasExactly(e as unknown as Record<string, unknown>, ENTRY_FIELDS)) {
    return `bootstrap entry must carry exactly ${ENTRY_FIELDS.join(", ")} (system-manifest/1 §6)`;
  }
  if (typeof e.kid !== "string" || !ASCII_ID_RE.test(e.kid)) {
    return "bootstrap entry kid must be a non-empty ASCII string (system-manifest/1 §7.1)";
  }
  if (typeof e.valid_from !== "string" || !RFC3339_UTC.test(e.valid_from) || Number.isNaN(Date.parse(e.valid_from))) {
    return "bootstrap entry valid_from must be an RFC 3339 UTC timestamp ending in Z (system-manifest/1 §7.4)";
  }
  // bootstrap entry's predecessor/successor members are null.
  if (
    e.predecessor_kid !== null ||
    e.successor_kid !== null ||
    e.predecessor_signatures !== null ||
    e.predecessor_manifest_fingerprint !== null ||
    e.valid_until !== null
  ) {
    return "bootstrap entry predecessor_kid/successor_kid/predecessor_signatures/predecessor_manifest_fingerprint/valid_until MUST all be null";
  }
  if (e.algorithm !== PROFILE_P256_MLDSA65) {
    return `bootstrap entry algorithm "${e.algorithm}" is not the supported composite profile "${PROFILE_P256_MLDSA65}"`;
  }
  // quorum {k,n}: 2 ≤ k ≤ n.
  const q = e.quorum;
  if (
    !isPlainObject(q) ||
    !hasExactly(q as unknown as Record<string, unknown>, QUORUM_FIELDS) ||
    !Number.isInteger(q.k) || !Number.isInteger(q.n) || q.k < 2 || q.k > q.n
  ) {
    return `bootstrap entry quorum invalid: expected {k,n} with 2 ≤ k ≤ n, got ${JSON.stringify(q)}`;
  }
  // members: exactly n elements, unique member_kid, correct key byte lengths.
  if (!Array.isArray(e.members) || e.members.length !== q.n) {
    return `bootstrap entry members MUST have exactly n (${q.n}) elements; got ${
      Array.isArray(e.members) ? e.members.length : "non-array"
    }`;
  }
  const seen = new Set<string>();
  for (const m of e.members as unknown[]) {
    if (!isPlainObject(m) || !hasExactly(m, MEMBER_FIELDS)) {
      return `each bootstrap member must carry exactly ${MEMBER_FIELDS.join(", ")} (system-manifest/1 §6)`;
    }
    if (typeof m.member_kid !== "string" || !ASCII_ID_RE.test(m.member_kid) || seen.has(m.member_kid)) {
      return `bootstrap entry member_kid "${String(m.member_kid)}" is not a non-empty ASCII string or not unique`;
    }
    seen.add(m.member_kid);
    const keyError = memberKeyError(m.public_key_p256_b64, m.public_key_mldsa_b64);
    if (keyError) return `bootstrap entry member "${m.member_kid}" ${keyError}`;
  }
  return null;
}

/**
 * Verify statement_signatures meet the bootstrap entry's quorum
 * (system-foundation/1, system-manifest/1): count DISTINCT members
 * whose composite signature verifies over M'(SHA3-256(JCS(manifest payload))); accept
 * iff that count ≥ k. The manifest payload includes the system_domain_capacity_key_*
 * members, so a capacity-key swap with intact signatures fails here.
 */
function verifyStatementQuorum(
  foundation: SystemFoundation,
  bootstrapEntry: ManifestEntry,
  config: SystemDomainConfig,
  builder: ResultBuilder
): boolean {
  // capacity keys present + decode under the bootstrap composite profile.
  let capP256: Uint8Array;
  let capMldsa: Uint8Array;
  try {
    capP256 = base64Decode(foundation.system_domain_capacity_key_p256_b64);
    capMldsa = base64Decode(foundation.system_domain_capacity_key_mldsa_b64);
  } catch {
    builder.fail(
      "FOUNDATION_SIGNATURE_VALID",
      "REJECTED",
      "system_domain_capacity_key_{p256,mldsa}_b64 are not valid RFC 4648 base64"
    );
    return false;
  }
  const capP256Ok = capP256.length === P256_SEC1_UNCOMPRESSED_LEN && capP256[0] === 0x04;
  if (!capP256Ok || capMldsa.length !== MLDSA65_PUBKEY_LEN) {
    builder.fail(
      "FOUNDATION_SIGNATURE_VALID",
      "REJECTED",
      "system_domain_capacity_key_p256_b64 must be a 65-byte SEC1 uncompressed point and " +
        "system_domain_capacity_key_mldsa_b64 a 1952-byte ML-DSA-65 key"
    );
    return false;
  }

  const payloadDigest = foundationPayloadDigest(foundation);

  const sigs = foundation.statement_signatures;
  if (!Array.isArray(sigs) || sigs.length === 0) {
    builder.fail(
      "FOUNDATION_SIGNATURE_VALID",
      "REJECTED",
      "statement_signatures missing or empty"
    );
    return false;
  }
  for (const entry of sigs as unknown[]) {
    if (!isPlainObject(entry) || !hasExactly(entry, MEMBER_SIGNATURE_FIELDS)) {
      builder.fail(
        "FOUNDATION_SIGNATURE_VALID",
        "REJECTED",
        `each statement_signatures element must carry exactly ${MEMBER_SIGNATURE_FIELDS.join(", ")}`
      );
      return false;
    }
  }

  const memberByKid = new Map(bootstrapEntry.members.map((m) => [m.member_kid, m]));
  const k = bootstrapEntry.quorum.k;

  const verifiedMembers = new Set<string>();
  for (const entry of sigs) {
    const member = memberByKid.get(entry.signer_member_kid);
    if (!member) continue; // non-member never counts
    if (verifiedMembers.has(entry.signer_member_kid)) continue; // dedup (counts once)

    const result = verifyComposite(bootstrapEntry.algorithm, payloadDigest, entry.signature, {
      classicalPubB64: member.public_key_p256_b64,
      mldsaPubB64: member.public_key_mldsa_b64,
    });
    if (result.valid) verifiedMembers.add(entry.signer_member_kid);
  }

  if (verifiedMembers.size < k) {
    builder.fail(
      "FOUNDATION_SIGNATURE_VALID",
      "REJECTED",
      `statement_signatures do not meet the bootstrap quorum: ${verifiedMembers.size} distinct member(s) ` +
        `verified, require ≥ k (${k})`
    );
    return false;
  }

  builder.pass("FOUNDATION_SIGNATURE_VALID");
  return true;
}

const SUCCESSOR_BINDING_PROFILE = "system-manifest/1:successor-binding";

/** The exact member set of the §9 payload, and of its nested objects. */
const SUCCESSOR_BINDING_FIELDS = [
  "binding_profile",
  "system_id",
  "predecessor_kid",
  "predecessor_manifest_fingerprint",
  "predecessor_manifest_sequence",
  "successor_kid",
  "successor_algorithm",
  "successor_quorum",
  "successor_members",
  "successor_valid_from",
];
const QUORUM_FIELDS = ["k", "n"];
const MEMBER_FIELDS = ["member_kid", "public_key_p256_b64", "public_key_mldsa_b64"];
const OBSERVATION_FIELDS = ["successor_binding", "predecessor_signatures"];
const MANIFEST_FIELDS = ["manifest_profile_id", "system_id", "manifest_sequence", "entries"];
const ENTRY_FIELDS = [
  "kid",
  "algorithm",
  "quorum",
  "members",
  "valid_from",
  "valid_until",
  "predecessor_kid",
  "successor_kid",
  "predecessor_signatures",
  "predecessor_manifest_fingerprint",
];
const MEMBER_SIGNATURE_FIELDS = ["signer_member_kid", "signature"];

/** RFC 3339 with an explicit `Z` zone (system-manifest/1 §7.4). */
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** True iff `obj` carries exactly `fields` — the closed schemas of §6 and §9. */
function hasExactly(obj: Record<string, unknown>, fields: string[]): boolean {
  const keys = Object.keys(obj);
  return keys.length === fields.length && fields.every((f) => Object.hasOwn(obj, f));
}

/**
 * Verify every supplied successor-binding observation against the predecessor
 * entry it claims (system-manifest/1 §9, §12.3, §13.5, §13.6). Returns an error
 * string for the first observation that fails, or null if all are authorized.
 *
 * The predecessor is the embedded bootstrap entry, at the bootstrap manifest's
 * fingerprint and sequence: an observation that names any other predecessor
 * cannot be verified from what this statement establishes, so it fails.
 */
function verifySuccessorObservations(
  observations: unknown,
  systemId: string,
  predecessor: ManifestEntry,
  predecessorFingerprint: string,
  predecessorSequence: number
): string | null {
  if (!Array.isArray(observations) || observations.length === 0) {
    return "successor_binding_observations must be a non-empty array when present";
  }
  for (let i = 0; i < observations.length; i++) {
    const err = verifySuccessorObservation(
      observations[i],
      systemId,
      predecessor,
      predecessorFingerprint,
      predecessorSequence
    );
    if (err) return `successor_binding_observations[${i}]: ${err}`;
  }
  return null;
}

function verifySuccessorObservation(
  observation: unknown,
  systemId: string,
  predecessor: ManifestEntry,
  predecessorFingerprint: string,
  predecessorSequence: number
): string | null {
  if (!isPlainObject(observation) || !hasExactly(observation, OBSERVATION_FIELDS)) {
    return `must be an object with exactly ${OBSERVATION_FIELDS.join(", ")}`;
  }
  const binding = observation.successor_binding;
  if (!isPlainObject(binding) || !hasExactly(binding, SUCCESSOR_BINDING_FIELDS)) {
    return "successor_binding does not carry exactly the members of the system-manifest/1 §9 payload";
  }

  // The binding must name the predecessor the verifier actually holds.
  if (binding.binding_profile !== SUCCESSOR_BINDING_PROFILE) {
    return `binding_profile must be "${SUCCESSOR_BINDING_PROFILE}"`;
  }
  if (binding.system_id !== systemId) {
    return `system_id "${String(binding.system_id)}" is not the statement's system_id`;
  }
  if (binding.predecessor_kid !== predecessor.kid) {
    return `predecessor_kid "${String(binding.predecessor_kid)}" is not the bootstrap entry "${predecessor.kid}"`;
  }
  if (binding.predecessor_manifest_fingerprint !== predecessorFingerprint) {
    return "predecessor_manifest_fingerprint is not the bootstrap manifest's fingerprint";
  }
  if (binding.predecessor_manifest_sequence !== predecessorSequence) {
    return `predecessor_manifest_sequence must be ${predecessorSequence}`;
  }

  // The successor quorum the predecessor authorizes (§7.3, §9, §13.5).
  if (binding.successor_algorithm !== PROFILE_P256_MLDSA65) {
    return `successor_algorithm "${String(binding.successor_algorithm)}" is not the supported composite profile`;
  }
  if (typeof binding.successor_kid !== "string" || binding.successor_kid.length === 0) {
    return "successor_kid must be a non-empty string";
  }
  if (binding.successor_kid === predecessor.kid) {
    return "successor_kid reuses the predecessor's kid";
  }
  const q = binding.successor_quorum;
  if (
    !isPlainObject(q) ||
    !hasExactly(q, QUORUM_FIELDS) ||
    !Number.isInteger(q.k) ||
    !Number.isInteger(q.n) ||
    (q.k as number) < 2 ||
    (q.k as number) > (q.n as number)
  ) {
    return `successor_quorum must be {k,n} with 2 ≤ k ≤ n, got ${JSON.stringify(q)}`;
  }
  const members = binding.successor_members;
  if (!Array.isArray(members) || members.length !== q.n) {
    return `successor_members must list exactly n (${String(q.n)}) members`;
  }
  const seenMembers = new Set<string>();
  for (const m of members) {
    if (!isPlainObject(m) || !hasExactly(m, MEMBER_FIELDS)) {
      return `each successor member must carry exactly ${MEMBER_FIELDS.join(", ")}`;
    }
    if (typeof m.member_kid !== "string" || m.member_kid.length === 0 || seenMembers.has(m.member_kid)) {
      return `successor member_kid "${String(m.member_kid)}" is missing or not unique`;
    }
    seenMembers.add(m.member_kid);
    const keyError = memberKeyError(m.public_key_p256_b64, m.public_key_mldsa_b64);
    if (keyError) return `successor member "${m.member_kid}" ${keyError}`;
  }
  if (typeof binding.successor_valid_from !== "string" || !RFC3339_UTC.test(binding.successor_valid_from)) {
    return "successor_valid_from must be an RFC 3339 UTC timestamp";
  }
  if (!(Date.parse(binding.successor_valid_from) > Date.parse(predecessor.valid_from))) {
    return "successor_valid_from must be strictly later than the predecessor's valid_from";
  }

  // The quorum rule (§12.3): ≥ k DISTINCT predecessor members whose composite
  // signature verifies over M'(SHA3-256(UTF-8(JCS(payload)))). A non-member never
  // counts; a repeated signer counts once; a signature that fails never counts.
  const sigs = observation.predecessor_signatures;
  if (!Array.isArray(sigs)) {
    return "predecessor_signatures must be an array";
  }
  const payloadDigest = digestHexBytes(jcsCanonicalizeBytes(binding));
  const memberByKid = new Map(predecessor.members.map((m) => [m.member_kid, m]));
  const verified = new Set<string>();
  for (const entry of sigs) {
    if (!isPlainObject(entry) || !hasExactly(entry, MEMBER_SIGNATURE_FIELDS)) {
      return `each predecessor signature must carry exactly ${MEMBER_SIGNATURE_FIELDS.join(", ")}`;
    }
    const kid = entry.signer_member_kid;
    if (typeof kid !== "string") continue;
    const member = memberByKid.get(kid);
    if (!member || verified.has(kid)) continue;
    const signature = entry.signature as MemberSignature["signature"];
    let valid = false;
    try {
      valid = verifyComposite(predecessor.algorithm, payloadDigest, signature, {
        classicalPubB64: member.public_key_p256_b64,
        mldsaPubB64: member.public_key_mldsa_b64,
      }).valid;
    } catch {
      valid = false;
    }
    if (valid) verified.add(kid);
  }
  const k = predecessor.quorum.k;
  if (verified.size < k) {
    return (
      `predecessor quorum not met: ${verified.size} distinct predecessor member(s) ` +
      `verified, require ≥ k (${k})`
    );
  }
  return null;
}

/** Component public-key checks of system-manifest/1 §7.3 / §13.5, or null. */
function memberKeyError(p256B64: unknown, mldsaB64: unknown): string | null {
  let p256: Uint8Array;
  let mldsa: Uint8Array;
  try {
    p256 = base64Decode(p256B64 as string);
    mldsa = base64Decode(mldsaB64 as string);
  } catch {
    return "has a component public key that is not valid RFC 4648 base64";
  }
  if (p256.length !== P256_SEC1_UNCOMPRESSED_LEN || p256[0] !== 0x04) {
    return "public_key_p256_b64 is not a SEC1 uncompressed P-256 point (65 bytes, 0x04)";
  }
  if (mldsa.length !== MLDSA65_PUBKEY_LEN) {
    return `public_key_mldsa_b64 length ${mldsa.length} != ${MLDSA65_PUBKEY_LEN}`;
  }
  return null;
}

/**
 * Detect equivocation among AUTHENTICATED observations (system-manifest/1
 * §12.5): two successor-bindings over the same index tuple (system_id,
 * predecessor_manifest_fingerprint, predecessor_manifest_sequence,
 * predecessor_kid) that differ in any of successor_kid / successor_quorum /
 * successor_members / successor_algorithm / successor_valid_from. Values are
 * compared as JCS bytes, so member order inside an object cannot hide or fake a
 * difference. Returns an explanatory string if equivocation is established.
 */
function detectEquivocation(
  observations: SuccessorBindingObservationInput[]
): string | null {
  const canon = (v: unknown): string =>
    new TextDecoder().decode(jcsCanonicalizeBytes(v));
  const conflictFields: (keyof SuccessorBindingPayload)[] = [
    "successor_kid",
    "successor_quorum",
    "successor_members",
    "successor_algorithm",
    "successor_valid_from",
  ];
  for (let i = 0; i < observations.length; i++) {
    for (let j = i + 1; j < observations.length; j++) {
      const a = observations[i].successor_binding;
      const b = observations[j].successor_binding;
      const sameTuple =
        a.system_id === b.system_id &&
        a.predecessor_manifest_fingerprint === b.predecessor_manifest_fingerprint &&
        a.predecessor_manifest_sequence === b.predecessor_manifest_sequence &&
        a.predecessor_kid === b.predecessor_kid;
      if (!sameTuple) continue;
      const differing = conflictFields.filter((f) => canon(a[f]) !== canon(b[f]));
      if (differing.length === 0) continue;
      return (
        "equivocation detected (system-manifest/1 §12.5): two successor-bindings, each " +
        "authorized by the predecessor quorum over the same index tuple, differ in " +
        `${differing.join(", ")} — implicated manifest versions are terminally invalid`
      );
    }
  }
  return null;
}

/**
 * Strict RFC 4648 base64 decode. Buffer.from(b64, "base64") silently ignores
 * non-alphabet characters; this rejects any non-standard-base64 input.
 */
function base64Decode(b64: string): Uint8Array {
  if (!b64 || b64.length === 0) {
    throw new Error("Empty base64 input");
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) {
    throw new Error("Invalid RFC 4648 base64: contains non-alphabet characters");
  }
  if (b64.length % 4 !== 0) {
    throw new Error("Invalid RFC 4648 base64: length is not a multiple of 4");
  }
  return new Uint8Array(Buffer.from(b64, "base64"));
}
