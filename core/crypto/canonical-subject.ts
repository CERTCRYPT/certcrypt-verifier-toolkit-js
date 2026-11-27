/**
 * `canonical_bytes(subject)` dispatch by subject profile (CCCP/1;
 * verifier-toolkit/1). The verifier recomputes these bytes from the
 * original material, hashes them to `subject_local_digest_hex`, and rebuilds the
 * certificate commitment to confirm the material matches.
 *
 * Supported profiles: `subject.binary/1`, `subject.text/1`, `subject.email/1`,
 * `subject.collection/1`, `subject.ai-decision/1`, and `subject.context-snapshot/1`.
 * An unsupported profile
 * MUST fail closed as UNSUPPORTED — the caller maps a thrown
 * `UnsupportedProfileError` to that outcome rather than falling back to another
 * profile.
 *
 * The subject canonicalization context is opaque bytes at the CCCP layer
 * (CCCP/1); CCCP/1 UTF-8/BOM rules govern CCCP-defined contexts, not
 * subject input. `subject.text/1` and `subject.email/1` therefore operate on the
 * RAW bytes and never decode/re-encode through a platform string (which could
 * alter bytes via U+FFFD substitution, normalization, or NUL truncation).
 */

import { jcsCanonicalizeBytes } from "./jcs.js";
import { strictJsonParse } from "../input/strict-json.js";
import {
  assertContextSnapshotPrecondition,
  assertCollectionPrecondition,
  assertAiDecisionPrecondition,
  SubjectPreconditionError,
} from "./subject-json-preconditions.js";

export const SUBJECT_BINARY = "subject.binary/1";
export const SUBJECT_TEXT = "subject.text/1";
export const SUBJECT_EMAIL = "subject.email/1";
export const SUBJECT_COLLECTION = "subject.collection/1";
export const SUBJECT_AI_DECISION = "subject.ai-decision/1";
export const SUBJECT_CONTEXT_SNAPSHOT = "subject.context-snapshot/1";
const AI_DECISION_MAX_BYTES = 1024 * 1024;

/** Profiles the toolkit supports for `canonical_bytes` recomputation. */
export const SUPPORTED_SUBJECT_PROFILES = [
  SUBJECT_BINARY,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  SUBJECT_CONTEXT_SNAPSHOT,
];

/**
 * Profiles whose canonical_bytes ARE the input bytes, unchanged.
 *
 * This is the precondition for hashing material INCREMENTALLY: a digest assembled from
 * chunks equals a digest of the whole buffer only when nothing is rewritten in between.
 * Every other profile fails it — `text/1` normalizes line endings and appends a terminator,
 * `email/1` unfolds headers across the whole message, and the JSON-object profiles
 * re-serialize the PARSED value under JCS, which is not even a byte transformation.
 *
 * It is a LIST, not a string comparison against `SUBJECT_BINARY`, because the property
 * belongs to the profile family and its versions: a future `subject.binary/2` that still
 * defines canonical_bytes as the exact input bytes belongs here, and one that does not must
 * NOT be added — the whole point of naming this separately from `SUPPORTED_SUBJECT_PROFILES`
 * is that supporting a profile and being streamable are different questions, decided here,
 * next to the switch that implements them.
 */
export const OPAQUE_BYTE_PROFILES: readonly string[] = [SUBJECT_BINARY];

/**
 * Whether `profile`'s canonical_bytes are its input bytes, so material under it may be
 * hashed in chunks instead of held whole in memory.
 */
export function isOpaqueByteProfile(profile: string): boolean {
  return OPAQUE_BYTE_PROFILES.includes(profile);
}

/** Thrown when a subject declares a profile the toolkit does not support. */
export class UnsupportedProfileError extends Error {
  readonly profile: string;
  constructor(profile: string) {
    super(`unsupported subject profile: ${profile}`);
    this.name = "UnsupportedProfileError";
    this.profile = profile;
  }
}

const CR = 0x0d;
const LF = 0x0a;
const SP = 0x20;
const HTAB = 0x09;

function isWsp(b: number): boolean {
  return b === SP || b === HTAB;
}

/**
 * subject.text/1 line-ending normalization: a single left-to-right pass
 * over the ORIGINAL bytes, CRLF longest-match before lone CR / lone LF.
 */
function normalizeLineEndings(input: Uint8Array): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < input.length) {
    if (input[i] === CR && input[i + 1] === LF) {
      out.push(CR, LF);
      i += 2;
    } else if (input[i] === CR) {
      out.push(CR, LF);
      i += 1;
    } else if (input[i] === LF) {
      out.push(CR, LF);
      i += 1;
    } else {
      out.push(input[i]);
      i += 1;
    }
  }
  return out;
}

/**
 * subject.text/1: normalize line endings to CRLF, then collapse the
 * trailing CRLF run to exactly one CRLF; all other bytes preserved.
 */
function canonicalizeText(material: Uint8Array): Uint8Array {
  const norm = normalizeLineEndings(material);
  // strip the maximal trailing run of CRLF, then append exactly one.
  let end = norm.length;
  while (end >= 2 && norm[end - 2] === CR && norm[end - 1] === LF) end -= 2;
  const out = norm.slice(0, end);
  out.push(CR, LF);
  return Uint8Array.from(out);
}

/**
 * subject.email/1: global CRLF normalization, split at the first
 * CRLF CRLF, unfold headers only as in RFC 5322 §2.2.3, body
 * trailing-terminator normalization, assemble headers || CRLF CRLF ||
 * body. Operates on raw bytes; no MIME decoding.
 */
function canonicalizeEmail(material: Uint8Array): Uint8Array {
  const m = Uint8Array.from(normalizeLineEndings(material));

  // Split at the FIRST CRLF CRLF (the four-byte delimiter may end at the
  // final byte, so the last candidate index is m.length - 4).
  let split = -1;
  for (let i = 0; i + 4 <= m.length; i++) {
    if (m[i] === CR && m[i + 1] === LF && m[i + 2] === CR && m[i + 3] === LF) {
      split = i;
      break;
    }
  }
  let headers: Uint8Array;
  let body: Uint8Array;
  if (split === -1) {
    headers = m;
    body = new Uint8Array(0);
  } else {
    headers = m.slice(0, split);
    body = m.slice(split + 4);
  }

  // Unfold headers only (RFC 5322 §2.2.3): each CRLF immediately followed
  // by a WSP byte is deleted (CRLF removed, the WSP preserved byte-for-byte,
  // including SP-vs-HTAB identity and run length).
  const hu: number[] = [];
  let i = 0;
  while (i < headers.length) {
    if (headers[i] === CR && headers[i + 1] === LF && isWsp(headers[i + 2])) {
      i += 2; // drop the CRLF; the WSP is emitted on the next iteration
    } else {
      hu.push(headers[i]);
      i += 1;
    }
  }

  // Body trailing-terminator normalization: a non-empty body ends in
  // exactly one CRLF (trailing CRLF run collapsed, or one appended if absent);
  // an empty body stays empty.
  let bodyOut: number[];
  if (body.length === 0) {
    bodyOut = [];
  } else {
    let end = body.length;
    while (end >= 2 && body[end - 2] === CR && body[end - 1] === LF) end -= 2;
    bodyOut = [...body.slice(0, end), CR, LF];
  }

  // Assembly: headers_unfolded || CRLF CRLF || body (delimiter always present).
  return Uint8Array.from([...hu, CR, LF, CR, LF, ...bodyOut]);
}

/**
 * Compute `canonical_bytes(subject)` for a subject under its declared profile.
 *
 * - `subject.binary/1`: the exact input bytes, opaque, no transformation
 *   (subject.binary/1). `material` MUST already be the raw bytes.
 * - `subject.text/1`: line-ending normalization + single trailing CRLF, byte
 *   preserved otherwise (subject.text/1). Operates on raw bytes.
 * - `subject.email/1`: global CRLF normalization, header/body split, RFC 5322
 *   header unfolding (WSP preserved), body trailing-terminator normalization,
 *   deterministic assembly (subject.email/1). Raw bytes.
 * - `subject.collection/1`: UTF-8 bytes of the RFC 8785 JCS serialization of the
 *   parsed JSON object (subject.collection/1). `material` is the JSON source
 *   bytes; it is parsed and re-canonicalized (canonicalize the value, not the
 *   source bytes).
 * - `subject.ai-decision/1`: the same JCS rule over the parsed decision record,
 *   after its field-set and string-only preconditions (subject.ai-decision/1).
 * - `subject.context-snapshot/1`: the same JCS rule over the parsed snapshot,
 *   which must carry no JSON number at any depth (subject.context-snapshot/1).
 *
 * Throws `UnsupportedProfileError` for any other declared profile.
 */
export function canonicalBytesForSubject(
  profile: string,
  material: Uint8Array,
): Uint8Array {
  switch (profile) {
    case SUBJECT_BINARY:
      // Opaque byte array: canonical_bytes == exact input bytes.
      return material;
    case SUBJECT_TEXT:
      return canonicalizeText(material);
    case SUBJECT_EMAIL:
      return canonicalizeEmail(material);
    case SUBJECT_COLLECTION:
    case SUBJECT_AI_DECISION:
    case SUBJECT_CONTEXT_SNAPSHOT: {
      if (profile === SUBJECT_AI_DECISION && material.byteLength > AI_DECISION_MAX_BYTES) {
        throw new SubjectPreconditionError(
          profile,
          `source material exceeds ${AI_DECISION_MAX_BYTES} bytes`,
        );
      }
      if (
        profile === SUBJECT_AI_DECISION &&
        material.byteLength >= 3 &&
        material[0] === 0xef && material[1] === 0xbb && material[2] === 0xbf
      ) {
        throw new SubjectPreconditionError(profile, "source material must not begin with a UTF-8 BOM");
      }
      // JSON-object subjects: parse the value, enforce the profile
      // precondition (field set + string-only discipline; fail-closed for any
      // other object), then JCS-canonicalize the VALUE (not the source bytes).
      // subject.ai-decision/1 and subject.collection/1 both define
      // canonical_bytes as RFC 8785 JCS of the parsed object; the string-only
      // discipline the precondition enforces keeps JCS free of number
      // serialization (subject.collection/1, subject.ai-decision/1).
      const text = new TextDecoder("utf-8", { fatal: true }).decode(material);
      // Strict parse: a member name repeated at any depth makes the material
      // non-conformant (the profile is undefined for it), so it fails closed
      // instead of being canonicalized from whichever duplicate a parser keeps.
      const value = strictJsonParse(text);
      if (profile === SUBJECT_COLLECTION) assertCollectionPrecondition(value);
      else if (profile === SUBJECT_AI_DECISION) assertAiDecisionPrecondition(value);
      // context-snapshot fixes no member set — the snapshot shape is CCVP/1's,
      // not this profile's. All it fixes here is the absence of JSON numbers.
      else assertContextSnapshotPrecondition(value);
      const canonical = jcsCanonicalizeBytes(value);
      if (profile === SUBJECT_AI_DECISION && canonical.byteLength > AI_DECISION_MAX_BYTES) {
        throw new SubjectPreconditionError(
          profile,
          `canonical material exceeds ${AI_DECISION_MAX_BYTES} bytes`,
        );
      }
      return canonical;
    }
    default:
      throw new UnsupportedProfileError(profile);
  }
}
