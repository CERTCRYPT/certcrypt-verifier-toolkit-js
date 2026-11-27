/**
 * CCVP/1 — issuance consistency against certified historical context.
 *
 * The problem this answers: a certificate signed three years ago by a key that
 * has since been retired. A CRL or OCSP responder answers it by being alive
 * today, which is exactly the dependency that fails over long horizons. CCVP
 * answers it from signed history instead — context snapshots declaring who was
 * eligible to issue, from when, and until when — so the question stays
 * answerable offline with no live authority.
 *
 * Four properties shape everything here:
 *
 * OPTIONAL, AND NEVER A VERDICT. CCVP grants no authority (CCVP/1 §0.2) and its
 * outcome never feeds `Issued` or `Independent` (verifier-toolkit/1 §11.3). A
 * certificate whose consistency is unknown is not thereby invalid: "Absence of
 * context snapshots MUST NOT invalidate cryptographic validity" (§10).
 *
 * CERTIFICATES IN, NOT VALUES. Both the target and every snapshot are signed
 * certificates, and each is verified here under the Issued route before it
 * counts. A snapshot's issuer is the key that signed it — `signer.id` plus the
 * composite key fingerprint — never a field it carries. The target names that
 * key in its signed `payload.context`, so a snapshot signed by anyone else is
 * outside the namespace whatever label it borrows (§5.2, §9 step 2).
 *
 * FORWARD ONLY. Context is selected by the certificate's issuance time, never
 * by now. Retiring a key today cannot retroactively unmake what it signed.
 *
 * INSTANTS, NOT STRINGS. Every timestamp is read as nanoseconds since the
 * epoch (§6.3). Comparing RFC 3339 strings orders `…00Z` after `…00.000Z`,
 * which name the same instant, and two verifiers would select differently.
 *
 * Three outcomes, and the third is not a failure:
 *   consistency-match      an applicable entry covers this issuance
 *   consistency-mismatch   a snapshot governs and no entry covers it
 *   consistency-unknown    no verification unit, no governing snapshot, or a
 *                          context that is equivocal or unreadable
 */

import type { SystemDomainConfig } from "../types/index.js";
import { verify } from "../verify.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";
import { canonicalBytesForSubject, SUBJECT_CONTEXT_SNAPSHOT } from "../crypto/canonical-subject.js";
import { toHex } from "../crypto/provider/bytes.js";

export type ConsistencyOutcome =
  | "consistency-match"
  | "consistency-mismatch"
  | "consistency-unknown";

/**
 * The declared context namespace of a target certificate (CCVP/1 §5.2): the
 * snapshot issuer by label and composite key fingerprint, and the context set.
 */
export interface ConsistencyNamespace {
  snapshot_issuer_id: string;
  snapshot_issuer_fingerprint_digest_hex: string;
  context_set_id: string;
}

/** The snapshot that governed the outcome. */
export interface SelectedSnapshot {
  snapshot_id: string;
  /** `S.payload.snapshot.issued_at` — the snapshot's effective context time. */
  issued_at: string;
}

export interface ConsistencyResult {
  outcome: ConsistencyOutcome;
  /** Why, in terms a caller can act on. */
  reason: string;
  /**
   * Whether the target verified under the Issued route. When false the outcome
   * is `consistency-unknown`: there is no issuer signature to bind (§5.3).
   */
  target_issued_valid: boolean;
  /** The namespace the target declares, when it declares a complete one. */
  namespace: ConsistencyNamespace | null;
  /** The governing snapshot, when one governed. */
  selected_snapshot: SelectedSnapshot | null;
  /** Index in the selected snapshot's `entries` of the entry that matched. */
  matched_entry_index: number | null;
  /** Candidates that were not Issued-valid and took no part (§9 step 1). */
  discarded_candidates: number;
}

const HEX64_RE = /^[0-9a-f]{64}$/;
/** CCSP/1 §7.3.1 form, which CCVP/1 §6.3 adopts for every timestamp. */
const TIMESTAMP_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/;
const ASCII_TOKEN_RE = /^[\x21-\x7e]+$/;

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Days from 1970-01-01 to a proleptic Gregorian date (no Date: it remaps years 0–99). */
function daysFromCivil(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor(yy / 400);
  const yoe = yy - era * 400;
  const doy = Math.floor((153 * (m + (m > 2 ? -3 : 9)) + 2) / 5) + d - 1;
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
  return era * 146097 + doe - 719468;
}

function daysInMonth(y: number, m: number): number {
  if (m === 2) return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
  return [4, 6, 9, 11].includes(m) ? 30 : 31;
}

/**
 * CCVP/1 §6.3: the instant a timestamp names, in nanoseconds since the epoch,
 * or null when the value is not a timestamp in the CCSP/1 `issued_at` form
 * naming a real instant.
 */
export function ccvpInstant(value: unknown): bigint | null {
  if (typeof value !== "string") return null;
  const m = TIMESTAMP_RE.exec(value);
  if (!m) return null;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || d < 1 || d > daysInMonth(y, mo) || h > 23 || mi > 59 || se > 59) {
    return null;
  }
  const seconds = BigInt(daysFromCivil(y, mo, d)) * 86400n + BigInt(h * 3600 + mi * 60 + se);
  return seconds * 1_000_000_000n + BigInt((m[7] ?? "").padEnd(9, "0"));
}

/** RFC 4648 base64 (standard alphabet, padded), or null. */
function decodeBase64(v: unknown): Uint8Array | null {
  if (typeof v !== "string" || v.length === 0 || v.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return null;
  const bin = atob(v);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * CCVP/1 §8.1: SHA3-256(pub_p256_bytes || pub_mldsa_bytes) over the decoded
 * keys of an issuer signature's signer — the construction of
 * composite-signature/1 §10. Only called on certificates that already verified,
 * so the keys decode.
 */
function compositeKeyFingerprint(signer: Json): string {
  const p256 = decodeBase64(signer.pub_p256_b64) ?? new Uint8Array();
  const mldsa = decodeBase64(signer.pub_mldsa_b64) ?? new Uint8Array();
  const both = new Uint8Array(p256.length + mldsa.length);
  both.set(p256, 0);
  both.set(mldsa, p256.length);
  return digestHexBytes(both);
}

/** A certificate that verified under the Issued route, with what CCVP reads. */
interface VerifiedCertificate {
  payload: Json;
  signature: Json;
  signer: Json;
  signerId: string;
  fingerprint: string;
}

function verifyIssuedCertificate(
  candidate: unknown,
  config: SystemDomainConfig | undefined
): VerifiedCertificate | null {
  if (!isObject(candidate)) return null;
  const result = verify(
    {
      verification_target_requested: "issued",
      input_mode: "artifact_set",
      base_certificate: candidate as never,
    },
    config
  );
  if (result.result_code !== "ISSUED_VALID") return null;
  const payload = candidate.payload as Json;
  const signature = (candidate.signatures as Json[])[0];
  const signer = signature.signer as Json;
  return {
    payload,
    signature,
    signer,
    signerId: signer.id as string,
    fingerprint: compositeKeyFingerprint(signer),
  };
}

/** CCVP/1 §5.2: the namespace triple, or null when incomplete or malformed. */
function readNamespace(payload: Json): ConsistencyNamespace | null {
  const ctx = payload.context;
  if (!isObject(ctx)) return null;
  const { snapshot_issuer_id, snapshot_issuer_fingerprint_digest_hex, context_set_id } = ctx;
  if (typeof snapshot_issuer_id !== "string") return null;
  if (typeof snapshot_issuer_fingerprint_digest_hex !== "string") return null;
  if (!HEX64_RE.test(snapshot_issuer_fingerprint_digest_hex)) return null;
  if (typeof context_set_id !== "string" || context_set_id.length === 0) return null;
  return { snapshot_issuer_id, snapshot_issuer_fingerprint_digest_hex, context_set_id };
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every((x) => typeof x === "string");
}

function isOptionalTimestamp(e: Json, key: string): boolean {
  return !(key in e) || e[key] === null || ccvpInstant(e[key]) !== null;
}

/** CCVP/1 §7.1: one entry in the form the specification defines. */
function isConformantEntry(e: unknown): e is Json {
  if (!isObject(e)) return false;
  if (typeof e.issuer_id !== "string" || e.issuer_id.length === 0) return false;
  if (typeof e.pub_fingerprint_digest_hex !== "string" || !HEX64_RE.test(e.pub_fingerprint_digest_hex)) {
    return false;
  }
  if (typeof e.status !== "string") return false;
  if (ccvpInstant(e.valid_from) === null) return false;
  if (!isOptionalTimestamp(e, "valid_to") || !isOptionalTimestamp(e, "revoked_at")) return false;
  if ("revocation_reason" in e && e.revocation_reason !== null && typeof e.revocation_reason !== "string") {
    return false;
  }
  if ("kid" in e) {
    const kid = e.kid;
    if (typeof kid !== "string" || !ASCII_TOKEN_RE.test(kid) || kid.length > 128) return false;
  }
  if ("roles" in e && !isStringArray(e.roles)) return false;
  if ("scope" in e) {
    if (!isObject(e.scope)) return false;
    if ("subject_profiles" in e.scope && !isStringArray(e.scope.subject_profiles)) return false;
  }
  return true;
}

/**
 * CCVP/1 §5.1 requirements 2–3 with §6, §6.3 and §7.1: the snapshot object is
 * well formed and is the one the issuer committed to in its
 * `subject.context-snapshot/1` subject.
 */
function isConformantSnapshot(cert: VerifiedCertificate): boolean {
  const snapshot = cert.payload.snapshot;
  if (!isObject(snapshot)) return false;

  const anchor = cert.payload.anchor as Json;
  const markers = (anchor.subjects as Json[]).filter((s) => s.profile === SUBJECT_CONTEXT_SNAPSHOT);
  if (markers.length !== 1) return false;
  let canonical: Uint8Array;
  try {
    // The profile's own preconditions: no JSON number at any depth. The value
    // reached here was parsed already, so repeated member names are the
    // caller's parser's to refuse (see strictJsonParse).
    canonical = canonicalBytesForSubject(
      SUBJECT_CONTEXT_SNAPSHOT,
      new TextEncoder().encode(JSON.stringify(snapshot))
    );
  } catch {
    return false;
  }
  const commitment = digestHexText((anchor.nonce_hex as string) + digestHexBytes(canonical));
  if (markers[0].commitment_digest_hex !== commitment) return false;

  if (typeof snapshot.context_set_id !== "string" || snapshot.context_set_id.length === 0) return false;
  if (typeof snapshot.snapshot_id !== "string" || snapshot.snapshot_id.length === 0) return false;
  if (ccvpInstant(snapshot.issued_at) === null) return false;
  if (!Array.isArray(snapshot.entries) || !snapshot.entries.every(isConformantEntry)) return false;
  return true;
}

/** CCVP/1 §8: is this entry applicable to the target? Every clause is a conjunct. */
function entryApplies(entry: Json, target: VerifiedCertificate, issuedAt: bigint): boolean {
  if (entry.issuer_id !== target.signerId) return false;
  if (entry.pub_fingerprint_digest_hex !== target.fingerprint) return false;
  // A kid narrows; it never admits. Without one in the entry, the signature's
  // kid plays no part.
  if ("kid" in entry && target.signature.kid !== entry.kid) return false;
  if (entry.status !== "active") return false;
  if ((ccvpInstant(entry.valid_from) as bigint) > issuedAt) return false;
  if (entry.valid_to !== undefined && entry.valid_to !== null) {
    if (!(issuedAt < (ccvpInstant(entry.valid_to) as bigint))) return false;
  }
  // CCSP/1 certificates carry one signature, under the issuer role.
  if (entry.roles !== undefined && !(entry.roles as string[]).includes("issuer")) return false;
  const scope = entry.scope as Json | undefined;
  if (scope?.subject_profiles !== undefined) {
    const allowed = scope.subject_profiles as string[];
    const profiles = ((target.payload.anchor as Json).subjects as Json[]).map((s) => s.profile);
    if (!profiles.some((p) => typeof p === "string" && allowed.includes(p))) return false;
  }
  return true;
}

/**
 * Evaluate the CCVP/1 consistency of one certificate under the namespace it
 * declares, against the candidate context snapshot certificates on hand.
 *
 * `certificate` and every element of `snapshots` are CCSP/1 certificates as
 * parsed JSON; parse them with `strictJsonParse` so a repeated member name
 * fails instead of being silently resolved. Each one is verified here under the
 * Issued route with `config` (the published production profile when omitted),
 * so ML-DSA-65 must be initialised (`initMlDsa65`) first.
 *
 * The result is reported beside, never instead of, the verdict of `verify()`:
 * no outcome here changes whether a certificate is Issued or Independent.
 */
export function verifyConsistency(
  certificate: unknown,
  snapshots: readonly unknown[],
  config?: SystemDomainConfig
): ConsistencyResult {
  const result = (
    outcome: ConsistencyOutcome,
    reason: string,
    extra: Partial<ConsistencyResult> = {}
  ): ConsistencyResult => ({
    outcome,
    reason,
    target_issued_valid: true,
    namespace: null,
    selected_snapshot: null,
    matched_entry_index: null,
    discarded_candidates: 0,
    ...extra,
  });

  const target = verifyIssuedCertificate(certificate, config);
  if (!target) {
    return result(
      "consistency-unknown",
      "the target certificate is not Issued-valid, so it has no issuer signature to bind " +
        "(CCVP/1 §5.3)",
      { target_issued_valid: false }
    );
  }

  const namespace = readNamespace(target.payload);
  if (!namespace) {
    return result(
      "consistency-unknown",
      "the certificate declares no complete context namespace in payload.context " +
        "(snapshot_issuer_id, snapshot_issuer_fingerprint_digest_hex, context_set_id)"
    );
  }
  const issuedAt = ccvpInstant((target.payload.anchor as Json).issued_at) as bigint;

  // §9 steps 1–2: verify every candidate, then keep the snapshots signed by the
  // key the namespace names, for its context set.
  let discarded = 0;
  const conformant: Json[] = [];
  const nonConformant: Json[] = [];
  for (const candidate of snapshots) {
    const cert = verifyIssuedCertificate(candidate, config);
    if (!cert) {
      discarded++;
      continue;
    }
    const subjects = (cert.payload.anchor as Json).subjects as Json[];
    const isSnapshot =
      "snapshot" in cert.payload || subjects.some((s) => s.profile === SUBJECT_CONTEXT_SNAPSHOT);
    if (!isSnapshot) continue;
    if (cert.signerId !== namespace.snapshot_issuer_id) continue;
    if (cert.fingerprint !== namespace.snapshot_issuer_fingerprint_digest_hex) continue;
    const snapshot = cert.payload.snapshot;
    if (!isObject(snapshot) || snapshot.context_set_id !== namespace.context_set_id) continue;
    (isConformantSnapshot(cert) ? conformant : nonConformant).push(snapshot);
  }
  const base = { namespace, discarded_candidates: discarded };

  // §9 step 4: the maximal effective instant at or before issuance.
  const eligible = conformant.filter((s) => (ccvpInstant(s.issued_at) as bigint) <= issuedAt);
  let maximal: bigint | null = null;
  for (const s of eligible) {
    const at = ccvpInstant(s.issued_at) as bigint;
    if (maximal === null || at > maximal) maximal = at;
  }

  // §9.1: a non-conformant snapshot from the namespace key is set aside only
  // when its effective time is readable and shows it cannot govern. It is never
  // skipped to reach an older snapshot it may have been meant to supersede.
  for (const s of nonConformant) {
    const at = ccvpInstant(s.issued_at);
    if (at !== null && (at > issuedAt || (maximal !== null && at < maximal))) continue;
    return result(
      "consistency-unknown",
      "a context snapshot signed by the namespace key does not conform to CCVP/1 and may " +
        "govern this issuance; it cannot be read and it cannot be skipped (CCVP/1 §9.1)",
      base
    );
  }

  if (maximal === null) {
    return result(
      "consistency-unknown",
      "no context snapshot in this namespace takes effect at or before the certificate's " +
        "issuance time",
      base
    );
  }

  // §9: a tie is one snapshot only if the canonical bytes agree; otherwise the
  // holder of the namespace key equivocated.
  const tied = eligible.filter((s) => ccvpInstant(s.issued_at) === maximal);
  const identities = new Set(tied.map((s) => toHex(jcsCanonicalizeBytes(s))));
  if (identities.size > 1) {
    return result(
      "consistency-unknown",
      `context equivocation: ${identities.size} distinct snapshots share the maximal ` +
        "effective time in this namespace",
      base
    );
  }

  const selected = tied[0];
  const selectedSnapshot: SelectedSnapshot = {
    snapshot_id: selected.snapshot_id as string,
    issued_at: selected.issued_at as string,
  };
  const entries = selected.entries as Json[];
  const index = entries.findIndex((e) => entryApplies(e, target, issuedAt));
  return index >= 0
    ? result(
        "consistency-match",
        `entry ${index} of snapshot ${selectedSnapshot.snapshot_id} (effective ` +
          `${selectedSnapshot.issued_at}) covers this issuance`,
        { ...base, selected_snapshot: selectedSnapshot, matched_entry_index: index }
      )
    : result(
        "consistency-mismatch",
        `snapshot ${selectedSnapshot.snapshot_id} (effective ${selectedSnapshot.issued_at}) ` +
          "governs this issuance and no entry covers the key that signed it",
        { ...base, selected_snapshot: selectedSnapshot }
      );
}
