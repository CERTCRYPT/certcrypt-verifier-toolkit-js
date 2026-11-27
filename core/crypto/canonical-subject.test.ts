/**
 * Conformance: canonical_bytes(subject) for every supported subject profile,
 * checked against the certcrypt-conformance primitive vectors
 * (`fixtures/primitives/subject-{text,email,binary,context-snapshot}`).
 *
 * Each vector pins input bytes -> canonical bytes -> subject_local_digest. These
 * tests assert the toolkit reproduces them byte-for-byte, so any divergence from
 * the cross-language contract is caught here.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalBytesForSubject,
  SUBJECT_BINARY,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  SUPPORTED_SUBJECT_PROFILES,
  OPAQUE_BYTE_PROFILES,
  isOpaqueByteProfile,
} from "./canonical-subject.js";
import { digestHexBytes, digestHexText } from "./digest.js";
import { jcsCanonicalizeBytes } from "./jcs.js";

const here = dirname(fileURLToPath(import.meta.url));
const PRIMITIVES = join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives");

function loadVectors(name: string): any | null {
  const p = join(PRIMITIVES, name, "vectors.json");
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf-8"));
}

function fromHex(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

function skipMsg(name: string): boolean {
  const v = loadVectors(name);
  if (!v) {
    console.error(`conformance vectors for ${name} not found alongside toolkit; skipping`);
    return true;
  }
  return false;
}

test("subject.text/1: canonical bytes + digest match conformance vectors", () => {
  if (skipMsg("subject-text")) return;
  const v = loadVectors("subject-text");
  for (const vec of v.vectors) {
    const input = fromHex(vec.input_hex);
    const canon = canonicalBytesForSubject(SUBJECT_TEXT, input);
    assert.equal(toHex(canon), vec.canonical_hex, `text canonical_hex [${vec.name}]`);
    assert.equal(
      digestHexBytes(canon),
      vec.subject_local_digest_hex,
      `text subject_local_digest [${vec.name}]`,
    );
  }
});

test("subject.email/1: canonical bytes + digest match conformance vectors", () => {
  if (skipMsg("subject-email")) return;
  const v = loadVectors("subject-email");
  for (const vec of v.vectors) {
    const input = fromHex(vec.input_hex);
    const canon = canonicalBytesForSubject(SUBJECT_EMAIL, input);
    assert.equal(toHex(canon), vec.canonical_hex, `email canonical_hex [${vec.name}]`);
    assert.equal(
      digestHexBytes(canon),
      vec.subject_local_digest_hex,
      `email subject_local_digest [${vec.name}]`,
    );
  }
});

test("subject.binary/1: identity canonical bytes + digest + commitment match vectors", () => {
  if (skipMsg("subject-binary")) return;
  const v = loadVectors("subject-binary");
  const nonceHex = v.nonce_hex;
  for (const vec of v.vectors) {
    const input = fromHex(vec.input_hex);
    const canon = canonicalBytesForSubject(SUBJECT_BINARY, input);
    // identity
    assert.equal(toHex(canon), vec.input_hex, `binary identity [${vec.name}]`);
    const local = digestHexBytes(canon);
    assert.equal(local, vec.subject_local_digest_hex, `binary subject_local_digest [${vec.name}]`);
    assert.equal(
      digestHexText(nonceHex + local),
      vec.expected_commitment_digest_hex,
      `binary commitment [${vec.name}]`,
    );
  }
});

test("subject.context-snapshot/1: JCS canonical bytes + digest match vectors", () => {
  if (skipMsg("subject-context-snapshot")) return;
  const v = loadVectors("subject-context-snapshot");
  for (const vec of v.vectors) {
    const canon = jcsCanonicalizeBytes(vec.snapshot_object);
    assert.equal(
      new TextDecoder().decode(canon),
      vec.expected_canonical_utf8,
      `context-snapshot canonical_utf8 [${vec.name}]`,
    );
    assert.equal(
      digestHexBytes(canon),
      vec.subject_local_digest_hex,
      `context-snapshot subject_local_digest [${vec.name}]`,
    );
  }
});

test("subject.collection/1: JCS canonical bytes + digest + commitment match vectors", () => {
  if (skipMsg("subject-collection")) return;
  const v = loadVectors("subject-collection");
  const nonceHex = v.nonce_hex;
  for (const vec of v.vectors) {
    // canonical_bytes(subject) = UTF-8 of RFC 8785 JCS of the collection subject
    // JSON value (subject.collection/1).
    const canon = jcsCanonicalizeBytes(vec.collection_subject);
    assert.equal(
      new TextDecoder().decode(canon),
      vec.expected_canonical_utf8,
      `collection canonical_utf8 [${vec.name}]`,
    );
    const sld = digestHexBytes(canon);
    assert.equal(sld, vec.expected_subject_local_digest_hex, `collection subject_local_digest [${vec.name}]`);
    // CCCP/1 commitment over nonce + subject-local digest.
    assert.equal(
      digestHexText(nonceHex + sld),
      vec.expected_commitment_digest_hex,
      `collection CCCP/1 commitment [${vec.name}]`,
    );
  }
});

test("subject.ai-decision/1: JCS canonical bytes + digest + commitment match vectors", () => {
  if (skipMsg("subject-ai-decision")) return;
  const v = loadVectors("subject-ai-decision");
  const nonceHex = v.nonce_hex;
  for (const vec of v.vectors) {
    const declared = new Map(
      [...vec.decision_record.input, ...vec.decision_record.output].map((part: any) => [part.id, part]),
    );
    for (const [id, material] of Object.entries(vec.part_materials)) {
      const part = declared.get(id) as {
        profile: string;
        material_nonce_hex: string;
        commitment_digest_hex: string;
      };
      const localDigest = digestHexBytes(
        canonicalBytesForSubject(part.profile, new TextEncoder().encode(material as string)),
      );
      assert.equal(
        digestHexText(part.material_nonce_hex + localDigest),
        part.commitment_digest_hex,
        `record part ${id} commitment matches material [${vec.name}]`,
      );
    }

    // The record itself canonicalizes deterministically.
    const canon = canonicalBytesForSubject(
      SUBJECT_AI_DECISION,
      new TextEncoder().encode(JSON.stringify(vec.decision_record)),
    );
    assert.equal(
      new TextDecoder().decode(canon),
      vec.expected_canonical_utf8,
      `ai-decision canonical_utf8 [${vec.name}]`,
    );
    const local = digestHexBytes(canon);
    assert.equal(local, vec.expected_subject_local_digest_hex, `ai-decision subject_local_digest [${vec.name}]`);
    assert.equal(
      digestHexText(nonceHex + local),
      vec.expected_commitment_digest_hex,
      `ai-decision commitment [${vec.name}]`,
    );
  }
});

test("unsupported profile throws (no silent fallback)", () => {
  assert.throws(
    () => canonicalBytesForSubject("subject.unknown/9", new Uint8Array([1, 2, 3])),
    /unsupported subject profile/,
  );
});

// Sanity: the supported profiles are exactly what we exercise above. The
// byte-oriented profiles (binary/text/email) accept any bytes; the JSON-object
// profiles (collection/ai-decision) need valid JSON and are content-checked by
// their own vector tests, so here we only assert the byte-oriented ones don't
// throw on trivial input.
test("supported profiles: binary, text, email, collection, ai-decision", () => {
  const jsonObjectProfiles = new Set([SUBJECT_COLLECTION, SUBJECT_AI_DECISION]);
  for (const p of [SUBJECT_BINARY, SUBJECT_TEXT, SUBJECT_EMAIL, SUBJECT_COLLECTION, SUBJECT_AI_DECISION]) {
    if (jsonObjectProfiles.has(p)) continue;
    assert.doesNotThrow(() => canonicalBytesForSubject(p, new Uint8Array([0x61])));
  }
});

test("opaque-byte profiles: streamable exactly when canonicalization is identity", () => {
  // The invariant that keeps `isOpaqueByteProfile` honest as profiles are added: a profile
  // may be streamed if and only if canonicalBytesForSubject RETURNS ITS INPUT unchanged.
  // Checking the actual function beats trusting the list — add a profile to
  // OPAQUE_BYTE_PROFILES that rewrites its material and this test fails, rather than a
  // consumer relying on that list silently accepting a digest over the wrong bytes.
  const probe = new TextEncoder().encode("line one\r\nline two\n");
  for (const profile of SUPPORTED_SUBJECT_PROFILES) {
    let identity: boolean;
    try {
      const out = canonicalBytesForSubject(profile, probe);
      // Same object AND same bytes: `text/1` can return an equal-length copy.
      identity =
        out === probe ||
        (out.length === probe.length && out.every((b, i) => b === probe[i]));
    } catch {
      // A profile that cannot even accept opaque bytes (the JSON ones) is not identity.
      identity = false;
    }
    assert.equal(
      isOpaqueByteProfile(profile),
      identity,
      `${profile}: streamable=${isOpaqueByteProfile(profile)} but canonicalization identity=${identity}`
    );
  }
});

test("opaque-byte profiles: every entry is a supported profile", () => {
  for (const p of OPAQUE_BYTE_PROFILES) {
    assert.ok(
      SUPPORTED_SUBJECT_PROFILES.includes(p),
      `${p} is declared streamable but is not a supported profile`
    );
  }
});

// ── Cross-language rejection contract: the primitive vectors' negative_cases ──
// Each JSON-object profile pins a negative_cases[] list of non-conformant inputs
// (JSON number/boolean/null token, member-set violations, grammar violations).
// The precondition MUST reject each — this is the shared rejection surface that
// keeps a non-JS implementation from silently accepting a number token. The
// positive_cases[] lists, where a profile carries one, pin the inputs the
// precondition MUST accept and the canonical bytes they produce.
import {
  assertCollectionPrecondition,
  assertAiDecisionPrecondition,
  assertContextSnapshotPrecondition,
  SubjectPreconditionError,
} from "./subject-json-preconditions.js";

const NEG_PROFILES: [string, string, (v: unknown) => void][] = [
  ["subject-collection", "collection_subject", assertCollectionPrecondition],
  ["subject-ai-decision", "decision_record", assertAiDecisionPrecondition],
  ["subject-context-snapshot", "snapshot_object", assertContextSnapshotPrecondition],
];

for (const [folder, objKey, precondition] of NEG_PROFILES) {
  test(`${folder}: every negative_cases entry is rejected (fail-closed)`, () => {
    if (skipMsg(folder)) return;
    const v = loadVectors(folder);
    const cases = v.negative_cases ?? [];
    assert.ok(cases.length > 0, `${folder} carries no negative_cases`);
    for (const nc of cases) {
      assert.throws(
        () => precondition(nc[objKey]),
        (e: unknown) => e instanceof SubjectPreconditionError,
        `${folder} negative case "${nc.name}" must be rejected`
      );
      assert.equal(nc.expected_outcome, "REJECTED", `${folder} "${nc.name}" outcome`);
    }
  });
}

for (const [folder, objKey, precondition] of NEG_PROFILES) {
  test(`${folder}: every positive_cases entry is accepted and canonicalizes as pinned`, () => {
    if (skipMsg(folder)) return;
    const v = loadVectors(folder);
    for (const pc of v.positive_cases ?? []) {
      assert.doesNotThrow(() => precondition(pc[objKey]), `${folder} positive case "${pc.name}"`);
      const canon = jcsCanonicalizeBytes(pc[objKey]);
      assert.equal(
        new TextDecoder().decode(canon),
        pc.expected_canonical_bytes_utf8,
        `${folder} positive case "${pc.name}" canonical bytes`,
      );
      assert.equal(digestHexBytes(canon), pc.expected_digest_hex, `${folder} positive case "${pc.name}" digest`);
    }
  });
}
