/**
 * Element-level inclusion for `collection.merkle-sha3-256/1`
 * (verifyCollectionInclusion). This is the capacity the public post
 * `from-proof-to-structure` leads on: ANY declared element of a collection is
 * checked on its own — one leaf + its path + the declared root — WITHOUT
 * supplying the rest of the collection.
 *
 * Positive cases are driven by the shared cross-implementation vectors
 * (certcrypt-conformance fixtures/primitives/collection-merkle): every declared
 * leaf of every vector must verify against the vector root with the vector's own
 * inclusion proof — and the recomputed root must be the SAME one collectionMerkleRoot
 * builds from the full ordered set, so element-level and whole-set agree.
 *
 * Negative cases mutate a real positive proof one axis at a time — false leaf,
 * false path, non-matching root, wrong path length, out-of-bounds / non-canonical
 * index, wrong proof_version — and require fail-closed rejection.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectionLeafHash,
  verifyCollectionInclusion,
  type CollectionInclusionProof,
} from "./collection-merkle.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS_DIR = process.env.CERTCRYPT_CONFORMANCE_DIR
  ? join(process.env.CERTCRYPT_CONFORMANCE_DIR, "primitives", "collection-merkle")
  : join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives", "collection-merkle");

interface MerkleVector {
  label: string;
  commitment_scheme: string;
  /** The collection salt bound into every leaf preimage (§10). */
  collection_salt_hex: string;
  leaf_profile: string;
  declared_cardinality: string;
  leaves_hex: string[];
  root: string;
  inclusion_proofs: CollectionInclusionProof[];
}

function hexToBytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return b;
}

function loadVectors(): { name: string; v: MerkleVector }[] {
  if (!existsSync(VECTORS_DIR)) return [];
  return readdirSync(VECTORS_DIR)
    .filter((f) => f.startsWith("vector-") && f.endsWith(".json"))
    .sort()
    .map((f) => ({ name: f, v: JSON.parse(readFileSync(join(VECTORS_DIR, f), "utf-8")) as MerkleVector }));
}

const vectors = loadVectors();

// A different, real 64-char lowercase hex digest to use as a "wrong" sibling/root.
const OTHER_HEX = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

test("collection-inclusion: conformance vectors are present", () => {
  assert.ok(vectors.length >= 6, `expected >= 6 merkle vectors, found ${vectors.length} in ${VECTORS_DIR}`);
});

for (const { name, v } of vectors) {
  // ── POSITIVE: every declared leaf verifies on its own against the root ──
  test(`collection-inclusion: ${name} (${v.label}) — every element verifies alone`, () => {
    assert.equal(v.inclusion_proofs.length, v.leaves_hex.length, "one inclusion proof per leaf");
    for (const proof of v.inclusion_proofs) {
      const idx = Number(proof.leaf_index);
      const leafBytes = hexToBytes(v.leaves_hex[idx]);
      const res = verifyCollectionInclusion(
        hexToBytes(v.collection_salt_hex),
        v.leaf_profile,
        leafBytes,
        proof,
        v.declared_cardinality,
        v.root,
      );
      assert.equal(res.valid, true, `leaf ${idx} must verify against the declared root (reason: ${res.reason})`);
      assert.equal(res.reason, null);
    }
  });

  // Pick the first leaf as the mutation base for this vector's negatives.
  const baseProof = v.inclusion_proofs[0];
  const baseIdx = Number(baseProof.leaf_index);
  const baseLeaf = hexToBytes(v.leaves_hex[baseIdx]);

  // ── NEGATIVE: false leaf (a byte flipped) must NOT verify ──
  test(`collection-inclusion: ${name} — false leaf rejected`, () => {
    const tampered = new Uint8Array(baseLeaf);
    tampered[0] = tampered[0] ^ 0x01; // flip one bit; distinct canonical bytes -> distinct leaf hash
    const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, tampered, baseProof, v.declared_cardinality, v.root);
    // Single-leaf tree: the root IS the leaf hash, so a false leaf changes the root -> mismatch.
    assert.equal(res.valid, false, "a leaf that is not the declared leaf must fail");
  });

  // ── NEGATIVE: non-matching declared root (non-matching declared root) ──
  test(`collection-inclusion: ${name} — non-matching root rejected`, () => {
    const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, baseLeaf, baseProof, v.declared_cardinality, OTHER_HEX);
    assert.equal(res.valid, false);
    assert.match(res.reason ?? "", /recomputed root differs/);
  });

  // ── NEGATIVE: wrong proof_version ──
  test(`collection-inclusion: ${name} — wrong proof_version rejected`, () => {
    const bad: CollectionInclusionProof = { ...baseProof, proof_version: "collection.merkle-sha3-256/2" };
    const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, baseLeaf, bad, v.declared_cardinality, v.root);
    assert.equal(res.valid, false);
    assert.match(res.reason ?? "", /proof_version differs/);
  });

  // ── NEGATIVE: out-of-bounds leaf_index ──
  test(`collection-inclusion: ${name} — out-of-bounds leaf_index rejected`, () => {
    const bad: CollectionInclusionProof = { ...baseProof, leaf_index: v.declared_cardinality };
    const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, baseLeaf, bad, v.declared_cardinality, v.root);
    assert.equal(res.valid, false);
    assert.match(res.reason ?? "", /out of bounds/);
  });

  // ── NEGATIVE: non-canonical leaf_index ──
  test(`collection-inclusion: ${name} — non-canonical leaf_index rejected`, () => {
    const bad: CollectionInclusionProof = { ...baseProof, leaf_index: `0${baseProof.leaf_index}` };
    const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, baseLeaf, bad, v.declared_cardinality, v.root);
    assert.equal(res.valid, false);
    assert.match(res.reason ?? "", /non-canonical/);
  });
}

// ── NEGATIVE cases that need a multi-leaf tree (paths with >= 1 sibling) ──
// Use the first vector whose leaves span at least two levels.
const multi = vectors.find(({ v }) => v.leaves_hex.length >= 4);

test("collection-inclusion: false path (tampered sibling) rejected", () => {
  assert.ok(multi, "need a vector with >= 4 leaves for a non-trivial path");
  const { v } = multi!;
  // Find a proof that actually carries at least one sibling.
  const proof = v.inclusion_proofs.find((p) => p.sibling_hashes.length >= 1)!;
  const idx = Number(proof.leaf_index);
  const leaf = hexToBytes(v.leaves_hex[idx]);
  const tampered: CollectionInclusionProof = {
    ...proof,
    sibling_hashes: [OTHER_HEX, ...proof.sibling_hashes.slice(1)],
  };
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, tampered, v.declared_cardinality, v.root);
  assert.equal(res.valid, false, "a tampered sibling must break the fold to root");
});

test("collection-inclusion: path too long rejected", () => {
  assert.ok(multi, "need a vector with >= 4 leaves");
  const { v } = multi!;
  const proof = v.inclusion_proofs.find((p) => p.sibling_hashes.length >= 1)!;
  const idx = Number(proof.leaf_index);
  const leaf = hexToBytes(v.leaves_hex[idx]);
  const tooLong: CollectionInclusionProof = {
    ...proof,
    sibling_hashes: [...proof.sibling_hashes, OTHER_HEX],
  };
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, tooLong, v.declared_cardinality, v.root);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? "", /too many sibling hashes/);
});

test("collection-inclusion: path too short rejected", () => {
  assert.ok(multi, "need a vector with >= 4 leaves");
  const { v } = multi!;
  const proof = v.inclusion_proofs.find((p) => p.sibling_hashes.length >= 2)!;
  const idx = Number(proof.leaf_index);
  const leaf = hexToBytes(v.leaves_hex[idx]);
  const tooShort: CollectionInclusionProof = {
    ...proof,
    sibling_hashes: proof.sibling_hashes.slice(0, -1),
  };
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, tooShort, v.declared_cardinality, v.root);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? "", /too few sibling hashes/);
});

test("collection-inclusion: reordered siblings (same length) rejected", () => {
  // A reordering attack keeps the path length correct but swaps two levels'
  // siblings — the fold must still not reach the root. Central to the post's
  // "checked on its own, without reopening anything" claim.
  const multi2 = vectors.find(({ v }) => v.inclusion_proofs.some((p) => p.sibling_hashes.length >= 2));
  assert.ok(multi2, "need a proof with >= 2 siblings to reorder");
  const { v } = multi2!;
  const proof = v.inclusion_proofs.find((p) => p.sibling_hashes.length >= 2)!;
  // Only meaningful if the two swapped siblings actually differ.
  const s = proof.sibling_hashes;
  if (s[0] === s[1]) return; // degenerate; skip
  const idx = Number(proof.leaf_index);
  const leaf = hexToBytes(v.leaves_hex[idx]);
  const swapped: CollectionInclusionProof = {
    ...proof,
    sibling_hashes: [s[1], s[0], ...s.slice(2)],
  };
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, swapped, v.declared_cardinality, v.root);
  assert.equal(res.valid, false, "reordered siblings must not fold to the root");
});

test("collection-inclusion: malformed sibling hash (not hex64) rejected", () => {
  assert.ok(multi, "need a vector with >= 4 leaves");
  const { v } = multi!;
  const proof = v.inclusion_proofs.find((p) => p.sibling_hashes.length >= 1)!;
  const idx = Number(proof.leaf_index);
  const leaf = hexToBytes(v.leaves_hex[idx]);
  const malformed: CollectionInclusionProof = {
    ...proof,
    sibling_hashes: ["not-hex", ...proof.sibling_hashes.slice(1)],
  };
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, malformed, v.declared_cardinality, v.root);
  assert.equal(res.valid, false);
  assert.match(res.reason ?? "", /malformed entry/);
});

test("collection-inclusion: declared root not hex64 rejected", () => {
  assert.ok(vectors.length >= 1);
  const { v } = vectors[0];
  const proof = v.inclusion_proofs[0];
  const leaf = hexToBytes(v.leaves_hex[Number(proof.leaf_index)]);
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, proof, v.declared_cardinality, "deadbeef");
  assert.equal(res.valid, false);
  assert.match(res.reason ?? "", /declared root is not a 64-char/);
});

// ── Cross-check: element-level agrees with a hand-built wrong leaf against a
// real multi-leaf root — a valid path for leaf i does NOT validate leaf j's bytes. ──
test("collection-inclusion: a valid path does not launder a different leaf", () => {
  assert.ok(multi, "need a vector with >= 4 leaves");
  const { v } = multi!;
  const proof = v.inclusion_proofs.find((p) => Number(p.leaf_index) === 0)!;
  // Use leaf 0's path but leaf 1's bytes: the recomputed root must NOT match.
  const wrongLeaf = hexToBytes(v.leaves_hex[1]);
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, wrongLeaf, proof, v.declared_cardinality, v.root);
  assert.equal(res.valid, false, "leaf 1's bytes with leaf 0's path must not fold to the root");
});

// Sanity: the leaf hash the fold starts from is the scheme's leaf hash, so a
// positive verify and collectionLeafHash agree on the same leaf.
test("collection-inclusion: single-leaf root equals the leaf hash", () => {
  const single = vectors.find(({ v }) => v.leaves_hex.length === 1);
  assert.ok(single, "need a single-leaf vector");
  const { v } = single!;
  const leaf = hexToBytes(v.leaves_hex[0]);
  assert.equal(collectionLeafHash(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf), v.root, "single-leaf root is the leaf hash");
  const res = verifyCollectionInclusion(hexToBytes(v.collection_salt_hex), v.leaf_profile, leaf, v.inclusion_proofs[0], v.declared_cardinality, v.root);
  assert.equal(res.valid, true);
});

// ── Shared cross-implementation negative oracle ──
// The SAME negative-inclusion.json the Python generator's emit_primitives.py checks
// (verify_collection_inclusion). Every case's verdict MUST equal expected_valid, so
// -js and the reference oracle agree on the whole rejection surface, not just on
// the positive vectors.
interface NegativeCase {
  name: string;
  /** Overrides the document-level salt when present (the empty-salt case). */
  collection_salt_hex?: string;
  expected_valid: boolean;
  reason_class: string | null;
  leaf_hex: string;
  declared_cardinality: string;
  root: string;
  proof: CollectionInclusionProof;
}
interface NegativeDoc {
  leaf_profile: string;
  collection_salt_hex: string;
  cases: NegativeCase[];
}

test("collection-inclusion: negative-inclusion.json oracle agrees case-by-case", () => {
  const path = join(VECTORS_DIR, "negative-inclusion.json");
  assert.ok(existsSync(path), `expected shared negative oracle at ${path}`);
  const doc = JSON.parse(readFileSync(path, "utf-8")) as NegativeDoc;
  assert.ok(doc.cases.length >= 10, "expected the full negative surface");
  let sawPositive = false;
  let sawNegative = false;
  for (const c of doc.cases) {
    const res = verifyCollectionInclusion(
      hexToBytes(c.collection_salt_hex ?? doc.collection_salt_hex),
      doc.leaf_profile,
      hexToBytes(c.leaf_hex),
      c.proof,
      c.declared_cardinality,
      c.root,
    );
    assert.equal(
      res.valid,
      c.expected_valid,
      `case ${c.name}: expected valid=${c.expected_valid}, got ${res.valid} (reason: ${res.reason})`,
    );
    if (c.expected_valid) sawPositive = true;
    else sawNegative = true;
  }
  assert.ok(sawPositive, "oracle must include a control positive");
  assert.ok(sawNegative, "oracle must include negative cases");
});
