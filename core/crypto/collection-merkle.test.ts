/**
 * Conformance parity for `collection.merkle-sha3-256/1` against the canonical
 * cross-implementation vectors (certcrypt-conformance fixtures/primitives/collection-merkle,
 * copied verbatim from the scheme spec's fixtures/v1 oracle). Each vector pins one
 * branch of the algorithm — single leaf, balanced 2/4/1024, odd-width promotion at
 * level 0 and at levels 0+1 — so a regression in pairing, promotion, or the leaf/node
 * preimage is caught. The full-pipeline fixtures (P007, V038-V040) only exercise the
 * 3-leaf odd case; these vectors cover the other five branches.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import {
  collectionLeafHash,
  collectionNodeHash,
  collectionMerkleRoot,
} from "./collection-merkle.js";

const here = dirname(fileURLToPath(import.meta.url));
// CERTCRYPT_CONFORMANCE_DIR points at the conformance `fixtures/` dir (the same
// convention scripts/run-conformance.ts uses), NOT the repo root — so append
// only `primitives/...`, not `fixtures/primitives/...`.
const VECTORS_DIR =
  process.env.CERTCRYPT_CONFORMANCE_DIR
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
  inclusion_proofs: { proof_version: string; leaf_index: string; sibling_hashes: string[] }[];
}

function hexToBytes(hex: string): Uint8Array {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return b;
}

// Fold a leaf hash with its sibling path to the root (collection.merkle-sha3-256/1
// Odd-width promotion: at a level whose width is odd, the rightmost
// node is promoted UNCHANGED and contributes NO sibling entry — so the proof carries
// fewer siblings than the tree has levels. We walk the levels reconstructing each
// level's width from the leaf count, and only consume a sibling (pairing left/right by
// the index's low bit) when the current node is NOT that lone rightmost node.
function foldInclusion(
  leafHash: string,
  leafIndex: number,
  siblings: string[],
  leafCount: number,
): string {
  let acc = leafHash;
  let idx = leafIndex;
  let width = leafCount;
  let s = 0;
  while (width > 1) {
    const isLoneRightmost = width % 2 === 1 && idx === width - 1;
    if (!isLoneRightmost) {
      const sib = siblings[s++];
      acc = idx % 2 === 0 ? collectionNodeHash(acc, sib) : collectionNodeHash(sib, acc);
    }
    // else: promoted unchanged (no sibling consumed).
    idx = Math.floor(idx / 2);
    width = Math.ceil(width / 2);
  }
  return acc;
}

function loadVectors(): { name: string; v: MerkleVector }[] {
  if (!existsSync(VECTORS_DIR)) return [];
  return readdirSync(VECTORS_DIR)
    .filter((f) => f.startsWith("vector-") && f.endsWith(".json"))
    .sort()
    .map((f) => ({ name: f, v: JSON.parse(readFileSync(join(VECTORS_DIR, f), "utf-8")) as MerkleVector }));
}

const vectors = loadVectors();

test("collection.merkle-sha3-256/1: conformance vectors are present", () => {
  assert.ok(vectors.length >= 6, `expected >= 6 merkle vectors, found ${vectors.length} in ${VECTORS_DIR}`);
});

for (const { name, v } of vectors) {
  test(`collection.merkle-sha3-256/1: ${name} (${v.label}) — root reconstructs`, () => {
    assert.equal(v.commitment_scheme, "collection.merkle-sha3-256/1");
    assert.equal(v.leaves_hex.length, Number(v.declared_cardinality), "leaf count == declared_cardinality");
    const leafHashes = v.leaves_hex.map((h) => collectionLeafHash(hexToBytes(v.collection_salt_hex), v.leaf_profile, hexToBytes(h)));
    assert.equal(collectionMerkleRoot(leafHashes), v.root, "recomputed root matches the vector root");
  });

  test(`collection.merkle-sha3-256/1: ${name} — every inclusion proof folds to root`, () => {
    const leafHashes = v.leaves_hex.map((h) => collectionLeafHash(hexToBytes(v.collection_salt_hex), v.leaf_profile, hexToBytes(h)));
    assert.equal(v.inclusion_proofs.length, leafHashes.length, "one inclusion proof per leaf");
    for (const ip of v.inclusion_proofs) {
      const idx = Number(ip.leaf_index);
      const folded = foldInclusion(leafHashes[idx], idx, ip.sibling_hashes, leafHashes.length);
      assert.equal(folded, v.root, `inclusion proof for leaf ${idx} folds to the committed root`);
    }
  });
}
