/**
 * Original-material verification against the conformance primitive vectors
 * (`certcrypt-conformance/fixtures/primitives/original-material`).
 *
 * The vectors pin canonical_bytes, leaf hashes, collection root, and CCCP
 * commitments. These tests assert the toolkit reproduces them byte-for-byte and
 * that the negative cases (cardinality lie, tampered leaf, tampered subject)
 * fail closed with the outcomes the profile fixes (verifier-toolkit/1 §8.5.3).
 */

import { RULES_2026_01_SUBJECT_PROFILES } from "../config/default.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import {
  collectionLeafHash,
  collectionMerkleRoot,
} from "../crypto/collection-merkle.js";
import {
  canonicalBytesForSubject,
  SUBJECT_BINARY,
  SUBJECT_TEXT,
  SUBJECT_EMAIL,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
} from "../crypto/canonical-subject.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";
import { verifyOriginalMaterial } from "./verify-original-material.js";
import { ResultBuilder } from "../result/builder.js";
import type { BaseCertificate, SubjectMaterialMap, VerifierRequest } from "../types/index.js";

const REQ: VerifierRequest = {
  verification_target_requested: "issued",
  input_mode: "artifact_set",
};

function freshBuilder(): ResultBuilder {
  return new ResultBuilder(REQ);
}

const here = dirname(fileURLToPath(import.meta.url));
const PRIMITIVES = join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives");
const enc = (s: string) => new TextEncoder().encode(s);

function loadVectors(name: string): any | null {
  const p = join(PRIMITIVES, name, "vectors.json");
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf-8"));
}

test("original-material: leaf hashes, root, and commitments match the pinned conformance vectors", () => {
  const v = loadVectors("original-material");
  if (!v) {
    console.error("conformance not found alongside toolkit; skipping");
    return;
  }
  const nonceHex = v.nonce_hex;

  const bin = v.subjects.find((s: any) => s.profile === SUBJECT_BINARY);
  const binCanon = canonicalBytesForSubject(SUBJECT_BINARY, enc(bin.material_utf8));
  const binLocal = digestHexBytes(binCanon);
  assert.equal(binLocal, bin.expected_subject_local_digest_hex, "binary subject_local_digest");
  assert.equal(
    digestHexText(nonceHex + binLocal),
    bin.expected_commitment_digest_hex,
    "binary commitment",
  );

  const coll = v.subjects.find((s: any) => s.profile === SUBJECT_COLLECTION);
  const leafHashes = coll.leaf_materials_utf8.map((m: string) =>
    collectionLeafHash(enc(nonceHex), coll.leaf_profile, canonicalBytesForSubject(coll.leaf_profile, enc(m))),
  );
  assert.deepEqual(leafHashes, coll.expected_leaf_hashes, "collection leaf hashes");

  const root = collectionMerkleRoot(leafHashes);
  assert.equal(root, coll.expected_root, "collection root");

  const collCanon = canonicalBytesForSubject(
    SUBJECT_COLLECTION,
    enc(JSON.stringify(coll.collection_object)),
  );
  assert.equal(
    new TextDecoder().decode(collCanon),
    coll.expected_collection_canonical_utf8,
    "collection JCS canonical bytes",
  );
  const collLocal = digestHexBytes(collCanon);
  assert.equal(collLocal, coll.expected_subject_local_digest_hex, "collection subject_local_digest");
  assert.equal(
    digestHexText(nonceHex + collLocal),
    coll.expected_commitment_digest_hex,
    "collection commitment",
  );
});

/** Build a certificate carrying the two pinned subjects + the matching map. */
function buildCertAndMaterial(v: any): { cert: BaseCertificate; material: SubjectMaterialMap } {
  const bin = v.subjects.find((s: any) => s.profile === SUBJECT_BINARY);
  const coll = v.subjects.find((s: any) => s.profile === SUBJECT_COLLECTION);
  const cert = {
    schema: "certcrypt-certificate",
    payload: {
      anchor: {
        issued_at: "2026-06-16T12:00:00Z",
        nonce_hex: v.nonce_hex,
        subjects: [
          { profile: bin.profile, commitment_digest_hex: bin.expected_commitment_digest_hex },
          {
            profile: coll.profile,
            commitment_digest_hex: coll.expected_commitment_digest_hex,
            // §7: the descriptor rides INSIDE the signed subject; the verifier reads it
            // from here, never from the delivery.
            collection: coll.collection_object,
          },
        ],
      },
    },
    signatures: [],
  } as unknown as BaseCertificate;

  const material: SubjectMaterialMap = new Map();
  material.set(0, enc(bin.material_utf8));
  // The delivery is the ordered leaf bytes.
  material.set(1, {
    leaves: coll.leaf_materials_utf8.map((m: string) => enc(m)),
  });
  return { cert, material };
}

/**
 * Read the outcome of ORIGINAL_MATERIAL_COMPARISON_VALID via the public result.
 * Since it is the only check this module adds, the result's failure code (when
 * failed) is exactly that check's classification, and `failed_check_ids`
 * includes it.
 */
function outcome(builder: ResultBuilder): { failed: boolean; code: string } {
  const r = builder.build();
  const failed = r.failed_check_ids.includes("ORIGINAL_MATERIAL_COMPARISON_VALID");
  return { failed, code: r.result_code };
}

test("original-material: honest material passes ORIGINAL_MATERIAL_COMPARISON_VALID", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  assert.equal(outcome(builder).failed, false);
});

test("original-material: cardinality lie fails closed", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  // Deliver 2 leaves while declared_cardinality is "3".
  const coll = material.get(1) as { collection: unknown; leaves: Uint8Array[] };
  material.set(1, { collection: coll.collection, leaves: coll.leaves.slice(0, 2) });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "REJECTED");
});

test("original-material: tampered leaf fails closed", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const coll = material.get(1) as { collection: unknown; leaves: Uint8Array[] };
  material.set(1, { collection: coll.collection, leaves: [enc("TAMPERED"), coll.leaves[1], coll.leaves[2]] });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "ISSUED_INVALID");
});

test("original-material: tampered binary subject fails closed", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  material.set(0, enc("hello certcrypt binary subject TAMPERED"));
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "ISSUED_INVALID");
});

function buildEmailCert(material: Uint8Array): BaseCertificate {
  const nonceHex = "b".repeat(64);
  const localDigest = digestHexBytes(canonicalBytesForSubject(SUBJECT_EMAIL, material));
  return {
    schema: "certcrypt-certificate",
    payload: {
      anchor: {
        issued_at: "2026-11-07T12:00:00Z",
        nonce_hex: nonceHex,
        subjects: [{
          profile: SUBJECT_EMAIL,
          commitment_digest_hex: digestHexText(nonceHex + localDigest),
        }],
      },
    },
    signatures: [],
  } as unknown as BaseCertificate;
}

test("original-material: subject.email/1 accepts only its specified canonical equivalences", () => {
  const emitted = enc("From: sender@example.test\r\nSubject: a long\r\n subject\r\n\r\nbody\r\n\r\n");
  const equivalentExport = enc("From: sender@example.test\nSubject: a long subject\n\nbody");
  const cert = buildEmailCert(emitted);
  const material: SubjectMaterialMap = new Map([[0, equivalentExport]]);
  const builder = freshBuilder();

  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);

  assert.equal(outcome(builder).failed, false);
  assert.equal(builder.build().complete_verification_against_original_material_passed, true);
});

test("original-material: subject.email/1 rejects a transit-mutated copy", () => {
  const emitted = enc("From: sender@example.test\r\nSubject: evidence\r\n\r\nbody\r\n");
  const received = enc(
    "Received: by recipient.example.test\r\nFrom: sender@example.test\r\nSubject: evidence\r\n\r\nbody\r\n",
  );
  const cert = buildEmailCert(emitted);
  const material: SubjectMaterialMap = new Map([[0, received]]);
  const builder = freshBuilder();

  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);

  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "ISSUED_INVALID");
});

test("original-material: material keyed beyond the declared subjects is REJECTED", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const n = cert.payload.anchor.subjects.length;
  material.set(n, enc("a subject the certificate does not declare"));
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "REJECTED");
});

test("original-material: a non-integer key is REJECTED", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  material.set(0.5, enc("between two subjects"));
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  assert.equal(outcome(builder).code, "REJECTED");
});

test("original-material: no material → not performed (not a failure)", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert } = buildCertAndMaterial(v);
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, null, builder, RULES_2026_01_SUBJECT_PROFILES);
  // No pass/fail check is emitted when material is absent — only a diagnostic.
  assert.equal(outcome(builder).failed, false);
});

// ---------------------------------------------------------------------------
// Independent reconstruction (breaks golden-vector circularity).
//
// The golden vector was generated with the toolkit's own primitives, so the
// parity test above only proves self-consistency. These build the
// collection.merkle-sha3-256/1 leaf/node preimages from scratch with node:crypto
// — NOT the toolkit functions — and assert the toolkit reproduces them. A shared
// bug in the toolkit's preimage construction would diverge here.
// ---------------------------------------------------------------------------

function u64beIndependent(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(n));
  return b;
}
const LEAF_TAG_I = Buffer.from("CERTCRYPT:collection.merkle-sha3-256/1:leaf", "utf8");
const NODE_TAG_I = Buffer.from("CERTCRYPT:collection.merkle-sha3-256/1:node", "utf8");

/** Independent leaf hash for a subject.binary/1 leaf (canonical = exact bytes). */
/** The salt this file's independent reimplementation and the toolkit both use.
 *  A stand-in for the anchor nonce: the scheme treats it as opaque bytes. */
const NONCE = "a".repeat(64);

function leafHashIndependent(materialUtf8: string): string {
  const salt = Buffer.from(NONCE, "utf8");
  const lp = Buffer.from("subject.binary/1", "utf8");
  const lc = Buffer.from(materialUtf8, "utf8");
  const pre = Buffer.concat([
    LEAF_TAG_I,
    u64beIndependent(salt.length),
    salt,
    u64beIndependent(lp.length),
    lp,
    u64beIndependent(lc.length),
    lc,
  ]);
  return createHash("sha3-256").update(pre).digest("hex");
}
function nodeHashIndependent(lHex: string, rHex: string): string {
  const pre = Buffer.concat([NODE_TAG_I, Buffer.from(lHex, "hex"), Buffer.from(rHex, "hex")]);
  return createHash("sha3-256").update(pre).digest("hex");
}

test("collection-merkle: toolkit matches an INDEPENDENT node:crypto reconstruction", () => {
  const materials = ["record-1", "record-2", "record-3"];
  // Toolkit path.
  const toolkitLeaves = materials.map((m) =>
    collectionLeafHash(enc(NONCE), SUBJECT_BINARY, canonicalBytesForSubject(SUBJECT_BINARY, enc(m))),
  );
  const toolkitRoot = collectionMerkleRoot(toolkitLeaves);
  // Independent path (no toolkit functions).
  const indepLeaves = materials.map(leafHashIndependent);
  const indepRoot = nodeHashIndependent(
    nodeHashIndependent(indepLeaves[0], indepLeaves[1]),
    indepLeaves[2],
  );
  assert.deepEqual(toolkitLeaves, indepLeaves, "leaf hashes diverge from independent calc");
  assert.equal(toolkitRoot, indepRoot, "root diverges from independent calc");
});

test("collection-merkle: single-leaf root is the leaf hash itself", () => {
  const leaf = collectionLeafHash(enc(NONCE), SUBJECT_BINARY, canonicalBytesForSubject(SUBJECT_BINARY, enc("only")));
  assert.equal(collectionMerkleRoot([leaf]), leaf, "single leaf root must equal the leaf hash");
  // Independent check.
  assert.equal(leaf, leafHashIndependent("only"));
});

test("collection-merkle: four-leaf (even, balanced) matches independent calc", () => {
  const materials = ["a", "b", "c", "d"];
  const toolkitRoot = collectionMerkleRoot(
    materials.map((m) => collectionLeafHash(enc(NONCE), SUBJECT_BINARY, canonicalBytesForSubject(SUBJECT_BINARY, enc(m)))),
  );
  const l = materials.map(leafHashIndependent);
  const indepRoot = nodeHashIndependent(
    nodeHashIndependent(l[0], l[1]),
    nodeHashIndependent(l[2], l[3]),
  );
  assert.equal(toolkitRoot, indepRoot);
});

test("collection-merkle: five-leaf (odd promotion across two levels) matches independent calc", () => {
  const materials = ["a", "b", "c", "d", "e"];
  const toolkitRoot = collectionMerkleRoot(
    materials.map((m) => collectionLeafHash(enc(NONCE), SUBJECT_BINARY, canonicalBytesForSubject(SUBJECT_BINARY, enc(m)))),
  );
  const l = materials.map(leafHashIndependent);
  // level0: [n(a,b), n(c,d), e]; level1: [n(n(a,b),n(c,d)), e]; level2: n(.., e)
  const n_ab = nodeHashIndependent(l[0], l[1]);
  const n_cd = nodeHashIndependent(l[2], l[3]);
  const n_abcd = nodeHashIndependent(n_ab, n_cd);
  const indepRoot = nodeHashIndependent(n_abcd, l[4]);
  assert.equal(toolkitRoot, indepRoot);
});

test("collection-merkle: empty tree throws", () => {
  assert.throws(() => collectionMerkleRoot([]), /empty tree/);
});

test("original-material: collection object with an extra field is REJECTED", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const coll = material.get(1) as { collection: Record<string, unknown>; leaves: Uint8Array[] };
  material.set(1, {
    collection: { ...coll.collection, sneaky_extra: "x" },
    leaves: coll.leaves,
  });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "REJECTED");
});

/* ── Prehashed material (streamed by the caller) ──────────────────────────────
   The browser path: a file too large for one ArrayBuffer is hashed chunk by chunk and only
   its digest is handed over. These pin that the verdict is IDENTICAL to the byte path, and
   that the type cannot be used where canonicalization would change the bytes. */

test("original-material: a prehashed binary subject verifies exactly like its bytes", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const bin = v.subjects.find((s: any) => s.profile === SUBJECT_BINARY);

  // Same digest a chunked read would produce — canonical_bytes IS the input for binary/1.
  const bytes = enc(bin.material_utf8);
  const streamed = digestHexBytes(canonicalBytesForSubject(SUBJECT_BINARY, bytes));
  material.set(0, {
    prehashed: true as const,
    subject_local_digest_hex: streamed,
    byte_length: bytes.length
  });

  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  assert.equal(outcome(builder).failed, false, "prehashed binary subject must pass");
});

test("original-material: a prehashed digest of the WRONG material still fails closed", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  material.set(0, {
    prehashed: true as const,
    subject_local_digest_hex: digestHexBytes(enc("not the certified material"))
  });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  // The same classification the byte path gives: material that does not match is a
  // negative VERDICT, not a malformed input.
  assert.equal(o.code, "ISSUED_INVALID");
});

test("original-material: a prehashed digest is REJECTED on a canonicalizing profile", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  // The collection subject at index 1 canonicalizes (JCS over the parsed value), so a
  // digest of raw bytes is a different value. Taking it would report a material mismatch
  // when the real fault is the caller's — hence REJECTED, not ISSUED_INVALID.
  material.set(1, {
    prehashed: true as const,
    subject_local_digest_hex: digestHexBytes(enc("anything"))
  });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "REJECTED");
});

test("original-material: a malformed prehashed digest is REJECTED, not compared", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const bad = ["", "abc", "A".repeat(64), "g".repeat(64), digestHexBytes(enc("x")).toUpperCase()];
  for (const hex of bad) {
    const { cert, material } = buildCertAndMaterial(v);
    material.set(0, { prehashed: true as const, subject_local_digest_hex: hex });
    const builder = freshBuilder();
    verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
    const o = outcome(builder);
    assert.equal(o.failed, true, `must fail for ${JSON.stringify(hex)}`);
    assert.equal(o.code, "REJECTED", `must be REJECTED for ${JSON.stringify(hex)}`);
  }
});

/* ── AI-decision nested material ───────────────────────────────────────────────
   The record is compared with the certificate; each disclosed part is then compared by
   id with the salted commitment the matched record declares, under the profile it declares. */

function buildAiDecision(): {
  cert: BaseCertificate;
  record: Uint8Array;
  materials: Map<string, Uint8Array>;
} | null {
  const v = loadVectors("subject-ai-decision");
  if (!v) return null;
  const vec = v.vectors[0];
  const cert = {
    schema: "certcrypt-certificate",
    payload: {
      anchor: {
        issued_at: "2026-06-16T12:00:00Z",
        nonce_hex: v.nonce_hex,
        subjects: [
          { profile: SUBJECT_AI_DECISION, commitment_digest_hex: vec.expected_commitment_digest_hex },
        ],
      },
    },
    signatures: [],
  } as unknown as BaseCertificate;
  return {
    cert,
    record: enc(JSON.stringify(vec.decision_record)),
    materials: new Map(
      Object.entries(vec.part_materials).map(([id, material]) => [id, enc(material as string)]),
    ),
  };
}

function runAi(cert: BaseCertificate, entry: unknown): { failed: boolean; code: string; complete: boolean } {
  const material: SubjectMaterialMap = new Map();
  material.set(0, entry as Uint8Array);
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const r = builder.build();
  return {
    failed: r.failed_check_ids.includes("ORIGINAL_MATERIAL_COMPARISON_VALID"),
    code: r.result_code,
    complete: r.complete_verification_against_original_material_passed === true,
  };
}

test("ai-decision material: record + disclosed parts that match pass", () => {
  const f = buildAiDecision();
  if (!f) return;
  const o = runAi(f.cert, { record: f.record, materials: f.materials });
  assert.equal(o.failed, false);
  assert.equal(o.complete, true);
});

test("ai-decision material: any or every part may be omitted", () => {
  const f = buildAiDecision();
  if (!f) return;
  assert.equal(runAi(f.cert, { record: f.record, materials: new Map() }).failed, false);
  const first = [...f.materials.entries()][0];
  assert.equal(runAi(f.cert, { record: f.record, materials: new Map([first]) }).failed, false);
});

test("ai-decision material: input recomputed under subject.text/1, not raw bytes", () => {
  const f = buildAiDecision();
  if (!f) return;
  // subject.text/1 reconciles LF and CRLF, so the same prompt with a CRLF line ending
  // still matches the digest the record declares.
  const [id, input] = [...f.materials.entries()][0];
  const crlf = enc(new TextDecoder().decode(input) + "\r\n");
  assert.equal(runAi(f.cert, { record: f.record, materials: new Map([[id, crlf]]) }).failed, false);
});

test("ai-decision material: an output that does not match fails closed", () => {
  const f = buildAiDecision();
  if (!f) return;
  const entries = [...f.materials.entries()];
  const o = runAi(f.cert, { record: f.record, materials: new Map([[entries.at(-1)![0], enc("rejected")]]) });
  assert.equal(o.failed, true);
  assert.equal(o.code, "ISSUED_INVALID");
});

test("ai-decision material: nested material is not opened when the record does not match", () => {
  const f = buildAiDecision();
  if (!f) return;
  const other = JSON.parse(new TextDecoder().decode(f.record));
  other.decision = "rejected";
  const o = runAi(f.cert, { record: enc(JSON.stringify(other)), materials: new Map([["unknown", enc("x")]]) });
  assert.equal(o.failed, true);
  assert.equal(o.code, "ISSUED_INVALID");
});

test("ai-decision nested material for a non-AI-decision subject is REJECTED", () => {
  const v = loadVectors("original-material");
  if (!v) return;
  const { cert, material } = buildCertAndMaterial(v);
  const bin = material.get(0) as Uint8Array;
  material.set(0, { record: bin, materials: new Map([["x", enc("x")]]) });
  const builder = freshBuilder();
  verifyOriginalMaterial(cert, material, builder, RULES_2026_01_SUBJECT_PROFILES);
  const o = outcome(builder);
  assert.equal(o.failed, true);
  assert.equal(o.code, "REJECTED");
});

test("ai-decision material: an unknown part id is REJECTED", () => {
  const f = buildAiDecision();
  if (!f) return;
  const o = runAi(f.cert, { record: f.record, materials: new Map([["unknown", enc("x")]]) });
  assert.equal(o.code, "REJECTED");
});

test("ai-decision material: a verifier-local prehashed binary part is accepted and is fail-closed", () => {
  const f = buildAiDecision();
  if (!f) return;
  const record = JSON.parse(new TextDecoder().decode(f.record)) as { input: { id: string; profile: string }[] };
  const binary = record.input.find((part) => part.profile === SUBJECT_BINARY);
  if (!binary) return;
  const binaryBytes = f.materials.get(binary.id)!;
  const verifierLocalDigest = digestHexBytes(binaryBytes);
  assert.equal(runAi(f.cert, {
    record: f.record,
    materials: new Map([[binary.id, { prehashed: true, subject_local_digest_hex: verifierLocalDigest }]]),
  }).failed, false);
  assert.equal(runAi(f.cert, {
    record: f.record,
    materials: new Map([[binary.id, { prehashed: true, subject_local_digest_hex: "0".repeat(64) }]]),
  }).code, "ISSUED_INVALID");
});

test("ai-decision material: prehashed delivery is rejected for non-binary and malformed digests", () => {
  const f = buildAiDecision();
  if (!f) return;
  const record = JSON.parse(new TextDecoder().decode(f.record)) as { input: { id: string; profile: string }[]; output: { id: string; profile: string }[] };
  const text = [...record.input, ...record.output].find((part) => part.profile === SUBJECT_TEXT)!;
  assert.equal(runAi(f.cert, {
    record: f.record,
    materials: new Map([[text.id, { prehashed: true, subject_local_digest_hex: "a".repeat(64) }]]),
  }).code, "REJECTED");
  const binary = record.input.find((part) => part.profile === SUBJECT_BINARY)!;
  assert.equal(runAi(f.cert, {
    record: f.record,
    materials: new Map([[binary.id, { prehashed: true, subject_local_digest_hex: "A".repeat(64) }]]),
  }).code, "REJECTED");
});
