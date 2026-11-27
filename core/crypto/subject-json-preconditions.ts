/**
 * Field-set / value-discipline preconditions for the JSON-object subject
 * profiles, enforced BEFORE canonicalization.
 *
 * Each profile spec states that structural conformance is a *precondition of
 * canonicalization*, not a separable later check: `canonical_bytes(subject)` is
 * defined ONLY for an object satisfying the profile in full, and for any
 * other object the profile does not apply and the implementation MUST fail
 * closed (subject.collection/1, subject.ai-decision/1, and the no-number
 * discipline of subject.context-snapshot/1).
 *
 * The verifier already rejects a non-conformant object downstream via commitment
 * mismatch, so this does not change which objects are accepted; it makes the reject happen at the
 * boundary with the correct reason (the profile does not apply) rather than as an
 * opaque digest mismatch, and it removes the only RFC 8785 divergence vector
 * (JSON numbers) that the string-only discipline exists to eliminate.
 *
 * A precondition failure throws `SubjectPreconditionError`; the caller maps it to
 * a fail-closed outcome exactly as it does `UnsupportedProfileError`.
 */

/** Thrown when a JSON-object subject violates its profile precondition. */
export class SubjectPreconditionError extends Error {
  readonly profile: string;
  constructor(profile: string, detail: string) {
    super(`subject precondition failed for ${profile}: ${detail}`);
    this.name = "SubjectPreconditionError";
    this.profile = profile;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Recursively assert the string-only value discipline of the two JSON-object
 * profiles with closed, string-valued member sets (subject.collection/1 and
 * subject.ai-decision/1): every value at any depth (object members, array
 * elements) MUST be a JSON string, object, or array. A JSON number, boolean, or
 * null token anywhere is non-conformant. This is what keeps RFC 8785 free of
 * number serialization. subject.context-snapshot/1 uses the narrower
 * `assertNoJsonNumber` below.
 */
function assertStringOnly(profile: string, value: unknown, path: string): void {
  if (typeof value === "string") return;
  if (Array.isArray(value)) {
    value.forEach((el, i) => assertStringOnly(profile, el, `${path}[${i}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      assertStringOnly(profile, value[k], path ? `${path}.${k}` : k);
    }
    return;
  }
  // number, boolean, null, or undefined — all forbidden.
  const kind = value === null ? "null" : typeof value;
  throw new SubjectPreconditionError(
    profile,
    `value at ${path || "(root)"} is a JSON ${kind}; every value must be a string, object, or array (no numbers/booleans/nulls)`,
  );
}

const CARDINALITY_MAX = 18446744073709551615n; // 2^64 − 1

/**
 * subject.collection/1: exactly four members — `commitment_scheme`, `root`,
 * `declared_cardinality` and the `leaves[]` array, whose entries each declare their
 * own `profile` and `commitment_digest_hex`. Also checks the commitment-scheme-specific
 * `root` shape, the `declared_cardinality` grammar, and that the cardinality agrees
 * with the number of leaves.
 */
export function assertCollectionPrecondition(value: unknown): void {
  const P = "subject.collection/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "subject is not a JSON object");
  }
  const REQUIRED = ["commitment_scheme", "root", "declared_cardinality", "leaves"];
  const STRING_MEMBERS = ["commitment_scheme", "root", "declared_cardinality"];
  const keys = Object.keys(value);
  for (const k of REQUIRED) {
    if (!(k in value)) throw new SubjectPreconditionError(P, `missing member "${k}"`);
  }
  for (const k of keys) {
    if (!REQUIRED.includes(k)) {
      throw new SubjectPreconditionError(P, `unexpected member "${k}" (exactly four members allowed)`);
    }
    if (STRING_MEMBERS.includes(k) && typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `member "${k}" must be a string`);
    }
  }
  // `leaves` is the one non-string member: an ordered array where each entry declares
  // its own profile and commitment (subject.collection/1 §7.4). Its position IS the
  // leaf index, so the array is load-bearing, not decorative.
  const leaves = value.leaves;
  if (!Array.isArray(leaves) || leaves.length === 0) {
    throw new SubjectPreconditionError(P, `"leaves" must be a non-empty array`);
  }
  for (let i = 0; i < leaves.length; i++) {
    const leaf = leaves[i] as Record<string, unknown> | null;
    if (typeof leaf !== "object" || leaf === null || Array.isArray(leaf)) {
      throw new SubjectPreconditionError(P, `"leaves[${i}]" must be an object`);
    }
    const lk = Object.keys(leaf);
    if (lk.length !== 2 || !("profile" in leaf) || !("commitment_digest_hex" in leaf)) {
      throw new SubjectPreconditionError(
        P,
        `"leaves[${i}]" must contain exactly "profile" and "commitment_digest_hex"`,
      );
    }
    for (const k of lk) {
      if (typeof leaf[k] !== "string") {
        throw new SubjectPreconditionError(P, `"leaves[${i}].${k}" must be a string`);
      }
    }
    if (!/^[0-9a-f]{64}$/.test(leaf.commitment_digest_hex as string)) {
      throw new SubjectPreconditionError(
        P,
        `"leaves[${i}].commitment_digest_hex" must be 64 lowercase hex characters`,
      );
    }
  }
  // §7.4.3: the economic layer reads declared_cardinality, so it must agree with the
  // array rather than be derived from it.
  if (String(leaves.length) !== value.declared_cardinality) {
    throw new SubjectPreconditionError(
      P,
      `"declared_cardinality" (${String(value.declared_cardinality)}) does not equal the number of leaves (${leaves.length})`,
    );
  }
  // declared_cardinality: canonical unsigned base-10, no sign, no leading
  // zeros, > 0, ≤ 2^64 − 1.
  const dc = value.declared_cardinality as string;
  if (!/^[1-9][0-9]*$/.test(dc)) {
    throw new SubjectPreconditionError(
      P,
      `"declared_cardinality" must be a canonical unsigned base-10 integer with no sign and no leading zeros`,
    );
  }
  if (BigInt(dc) > CARDINALITY_MAX) {
    throw new SubjectPreconditionError(P, `"declared_cardinality" exceeds 2^64 − 1`);
  }
  // for the sha3-256 merkle scheme, root is 64 lowercase hex chars.
  if (value.commitment_scheme === "collection.merkle-sha3-256/1") {
    if (!/^[0-9a-f]{64}$/.test(value.root as string)) {
      throw new SubjectPreconditionError(
        P,
        `"root" must be a 64-character lowercase hex string under collection.merkle-sha3-256/1`,
      );
    }
  }
  assertStringOnly(P, value, "");
}

/** Profiles an AI-decision part may declare. */
export const AI_DECISION_IO_PROFILES: readonly string[] = [
  "subject.text/1",
  "subject.binary/1",
  "subject.email/1",
  "subject.ai-decision/1",
];

const HEX64 = /^[0-9a-f]{64}$/;
const AI_PART_ID = /^[a-z][a-z0-9._-]{0,63}$/;
const MIME_ESSENCE = /^[a-z0-9!#$%&'*+.^_`|~-]+\/[a-z0-9!#$%&'*+.^_`|~-]+$/;
const AI_PART_KEYS = [
  "id", "role", "media_type", "profile", "material_nonce_hex", "commitment_digest_hex",
];
const AI_PART_MAX = 256;
const AI_PARAMETERS_MAX = 128;

/**
 * UTC, millisecond timestamp spelling required by subject.ai-decision/1.
 */
const DECIDED_AT = /^([0-9]{4})-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.([0-9]{3})Z$/;

function isValidGregorianUtcMillisecond(value: string): boolean {
  const match = DECIDED_AT.exec(value);
  if (!match) return false;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year === 0 || day === 0) return false;
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return day <= days[month - 1];
}

function assertAiPart(
  profile: string,
  part: unknown,
  path: string,
  ids: Set<string>,
  materialNonces: Set<string>,
): void {
  if (!isPlainObject(part)) {
    throw new SubjectPreconditionError(profile, `"${path}" must be an object`);
  }
  const keys = Object.keys(part);
  if (keys.length !== AI_PART_KEYS.length || AI_PART_KEYS.some((key) => !(key in part))) {
    throw new SubjectPreconditionError(
      profile,
      `"${path}" must contain exactly ${AI_PART_KEYS.map((key) => `"${key}"`).join(", ")}`,
    );
  }
  for (const key of keys) {
    if (!AI_PART_KEYS.includes(key)) {
      throw new SubjectPreconditionError(profile, `"${path}" has unexpected member "${key}"`);
    }
    if (typeof part[key] !== "string") {
      throw new SubjectPreconditionError(profile, `"${path}.${key}" must be a string`);
    }
  }
  const p = part as Record<string, string>;
  if (!AI_PART_ID.test(p.id)) {
    throw new SubjectPreconditionError(profile, `"${path}.id" is not a valid material id`);
  }
  if (ids.has(p.id)) {
    throw new SubjectPreconditionError(profile, `material id ${JSON.stringify(p.id)} is duplicated`);
  }
  ids.add(p.id);
  if (p.role.length === 0) {
    throw new SubjectPreconditionError(profile, `"${path}.role" must be non-empty`);
  }
  if (!MIME_ESSENCE.test(p.media_type)) {
    throw new SubjectPreconditionError(
      profile,
      `"${path}.media_type" must be a lowercase MIME essence without parameters`,
    );
  }
  if (!AI_DECISION_IO_PROFILES.includes(p.profile)) {
    throw new SubjectPreconditionError(profile, `"${path}.profile" is not an admitted part profile`);
  }
  if (!HEX64.test(p.material_nonce_hex)) {
    throw new SubjectPreconditionError(
      profile,
      `"${path}.material_nonce_hex" must be 64 lowercase hex characters`,
    );
  }
  if (materialNonces.has(p.material_nonce_hex)) {
    throw new SubjectPreconditionError(
      profile,
      `material nonce ${JSON.stringify(p.material_nonce_hex)} is duplicated`,
    );
  }
  materialNonces.add(p.material_nonce_hex);
  if (!HEX64.test(p.commitment_digest_hex)) {
    throw new SubjectPreconditionError(
      profile,
      `"${path}.commitment_digest_hex" must be 64 lowercase hex characters`,
    );
  }
}

/**
 * subject.ai-decision/1: exact record and part shapes, bounded flat parameters,
 * string-only values, part ids unique within the record, and a Gregorian UTC timestamp.
 */
export function assertAiDecisionPrecondition(value: unknown): void {
  const P = "subject.ai-decision/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "record is not a JSON object");
  }
  const REQUIRED = ["profile", "decision_id", "decided_at", "model", "observation_scope", "input", "output", "decision"];
  const OPTIONAL = ["parameters", "context", "started_at", "actor_id", "policy_ref"];
  const allowed = new Set([...REQUIRED, ...OPTIONAL]);
  for (const k of REQUIRED) {
    if (!(k in value)) throw new SubjectPreconditionError(P, `missing required member "${k}"`);
  }
  for (const k of Object.keys(value)) {
    if (!allowed.has(k)) {
      throw new SubjectPreconditionError(P, `unexpected member "${k}"`);
    }
  }
  if (value.profile !== P) {
    throw new SubjectPreconditionError(P, `"profile" must equal "${P}"`);
  }
  for (const k of ["profile", "decision_id", "decided_at", "observation_scope", "decision"] as const) {
    if (typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `member "${k}" must be a string`);
    }
  }
  if (!AI_PART_ID.test(value.decision_id as string)) {
    throw new SubjectPreconditionError(P, `"decision_id" is not a valid canonical token`);
  }
  if ((value.decision as string).length === 0) {
    throw new SubjectPreconditionError(P, `"decision" must be non-empty`);
  }
  if (!isValidGregorianUtcMillisecond(value.decided_at as string)) {
    throw new SubjectPreconditionError(
      P,
      `"decided_at" must be a valid Gregorian UTC timestamp at millisecond precision`,
    );
  }
  if ("started_at" in value) {
    if (typeof value.started_at !== "string" || !isValidGregorianUtcMillisecond(value.started_at)) {
      throw new SubjectPreconditionError(
        P,
        `"started_at" must be a valid Gregorian UTC timestamp at millisecond precision`,
      );
    }
    if (value.started_at > (value.decided_at as string)) {
      throw new SubjectPreconditionError(P, `"started_at" must not be later than "decided_at"`);
    }
  }
  // model: object with string id + provider, optional string version, no other members.
  assertNestedStringObject(P, value.model, "model", ["id", "provider"], ["version"]);
  for (const [key, member] of Object.entries(value.model as Record<string, string>)) {
    if (member.length === 0) {
      throw new SubjectPreconditionError(P, `"model.${key}" must be non-empty`);
    }
  }
  const ids = new Set<string>();
  const materialNonces = new Set<string>();
  let total = 0;
  for (const side of ["input", "output"] as const) {
    const parts = value[side];
    if (!Array.isArray(parts)) {
      throw new SubjectPreconditionError(P, `member "${side}" must be an array`);
    }
    if (parts.length === 0) {
      throw new SubjectPreconditionError(P, `member "${side}" must be a non-empty array`);
    }
    total += parts.length;
    parts.forEach((part, index) =>
      assertAiPart(P, part, `${side}[${index}]`, ids, materialNonces));
  }
  if (total < 1 || total > AI_PART_MAX) {
    throw new SubjectPreconditionError(P, `input and output must contain 1..${AI_PART_MAX} parts in total`);
  }
  // parameters (optional): opaque, issuer-defined names, but every member is a
  // string — no nested object or array.
  for (const mapName of ["parameters", "context"] as const) {
    if (!(mapName in value)) continue;
    const map = value[mapName];
    if (!isPlainObject(map)) {
      throw new SubjectPreconditionError(P, `"${mapName}" must be an object when present`);
    }
    const entries = Object.entries(map);
    if (entries.length > AI_PARAMETERS_MAX) {
      throw new SubjectPreconditionError(P, `"${mapName}" must contain at most ${AI_PARAMETERS_MAX} members`);
    }
    for (const [k, v] of entries) {
      if (typeof v !== "string") {
        throw new SubjectPreconditionError(
          P,
          `"${mapName}.${k}" must be a string (${mapName} members are flat strings)`,
        );
      }
    }
  }
  for (const k of ["actor_id", "policy_ref"] as const) {
    if (k in value && typeof value[k] !== "string") {
      throw new SubjectPreconditionError(P, `optional member "${k}" must be a string`);
    }
  }
  // The only arrays permitted by the closed shape are input and output. Every
  // remaining leaf is a string, which keeps JCS free of number serialization.
  assertStringOnly(P, value, "");
}

function assertNestedStringObject(
  profile: string,
  obj: unknown,
  name: string,
  required: string[],
  optional: string[],
): void {
  if (!isPlainObject(obj)) {
    throw new SubjectPreconditionError(profile, `member "${name}" must be an object`);
  }
  const allowed = new Set([...required, ...optional]);
  for (const k of required) {
    if (!(k in obj)) throw new SubjectPreconditionError(profile, `"${name}" missing member "${k}"`);
  }
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) {
      throw new SubjectPreconditionError(profile, `"${name}" has unexpected member "${k}"`);
    }
    if (typeof obj[k] !== "string") {
      throw new SubjectPreconditionError(profile, `"${name}.${k}" must be a string`);
    }
  }
}

/**
 * subject.context-snapshot/1: the only precondition this profile fixes at
 * the canonicalization boundary is that the value is a JSON object with no JSON
 * number at any depth (booleans and nulls are permitted). It does not fix a member set — the snapshot
 * shape is governed by the higher-layer protocol (CCVP/1), not this profile.
 */
export function assertContextSnapshotPrecondition(value: unknown): void {
  const P = "subject.context-snapshot/1";
  if (!isPlainObject(value)) {
    throw new SubjectPreconditionError(P, "snapshot is not a JSON object");
  }
  assertNoJsonNumber(P, value, "");
}

/**
 * `subject.context-snapshot/1` §7.1: no JSON NUMBER at any depth. Booleans and
 * nulls are permitted.
 *
 * Narrower than `assertStringOnly` on purpose, and the difference is normative.
 * That function serves `subject.collection/1` and `subject.ai-decision/1`, whose
 * member sets are closed and entirely string-valued. This profile fixes no member
 * set — the snapshot shape belongs to CCVP/1 — and §7 requires preserving "the
 * exact string, boolean, array, object, and null semantics of the input", while
 * §8 forbids coercing "booleans or nulls into strings". CCVP/1 §7.1 relies on
 * this: its normative entry example carries `valid_to: null` for an open-ended
 * eligibility window, and `revoked_at: null` for one never revoked.
 *
 * Rejecting nulls here would make the governing protocol's own example
 * non-conformant, and would force an open window to be spelled as a string —
 * exactly the coercion §8 prohibits. Only numbers are excluded, because number
 * serialization is the one RFC 8785 divergence vector across languages.
 */
function assertNoJsonNumber(profile: string, value: unknown, path: string): void {
  if (typeof value === "number") {
    throw new SubjectPreconditionError(
      profile,
      `value at ${path || "(root)"} is a JSON number; every numeric-looking value ` +
        `must be carried as a JSON string so RFC 8785 canonicalization converges ` +
        `across languages`,
    );
  }
  if (Array.isArray(value)) {
    value.forEach((el, i) => assertNoJsonNumber(profile, el, `${path}[${i}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const k of Object.keys(value)) {
      assertNoJsonNumber(profile, value[k], path ? `${path}.${k}` : k);
    }
  }
}
