import { digestHexBytes } from "./digest.js";

const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

/**
 * Compute leaf hash: SHA3-256(0x00 || canonical_leaf_preimage_bytes)
 * Per settlement.binding/1 section 6.
 */
export function computeLeafHash(canonicalBytes: Uint8Array): string {
  const prefixed = new Uint8Array(1 + canonicalBytes.length);
  prefixed.set(LEAF_PREFIX, 0);
  prefixed.set(canonicalBytes, 1);
  return digestHexBytes(prefixed);
}

const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * Compute internal node hash: SHA3-256(0x01 || left || right). Both inputs are
 * 64-char lowercase hex: hashes this module computed, or siblings
 * `verifyInclusionProof` has already checked.
 */
function computeNodeHash(leftHex: string, rightHex: string): string {
  const left = hexToBytes(leftHex);
  const right = hexToBytes(rightHex);
  const prefixed = new Uint8Array(1 + left.length + right.length);
  prefixed.set(NODE_PREFIX, 0);
  prefixed.set(left, 1);
  prefixed.set(right, 1 + left.length);
  return digestHexBytes(prefixed);
}

/**
 * Verify inclusion proof for a leaf in a Merkle tree of this construction (the
 * aggregated settlement tree of settlement.binding/1 section 6, and the
 * operation-key tree of holder-keyset.merkle-sha3-256/1).
 *
 * - sibling_hashes ordered bottom-up
 * - Orientation: an even index at a level is the left child, an odd one the right
 * - Odd cardinality: final child is promoted unchanged when it has no sibling
 *
 * Fail-closed, never throws: `treeSize` must be a safe integer >= 1 and
 * `leafIndex` a safe integer in [0, treeSize); the leaf hash, the root and every
 * sibling must be 64-char lowercase hex; every sibling must be consumed. An
 * index past the tree would otherwise fold as an alias of a real one.
 */
export function verifyInclusionProof(
  leafHash: string,
  leafIndex: number,
  siblingHashes: string[],
  expectedRoot: string,
  treeSize: number
): boolean {
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) return false;
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
  if (typeof leafHash !== "string" || !HEX64_RE.test(leafHash)) return false;
  if (typeof expectedRoot !== "string" || !HEX64_RE.test(expectedRoot)) return false;
  if (!Array.isArray(siblingHashes)) return false;
  for (const s of siblingHashes) {
    if (typeof s !== "string" || !HEX64_RE.test(s)) return false;
  }

  let currentHash = leafHash;
  let currentIndex = leafIndex;
  let siblingIndex = 0;
  let levelWidth = treeSize;

  while (levelWidth > 1) {
    const isRight = currentIndex % 2 === 1;
    const hasSibling = isRight || currentIndex + 1 < levelWidth;

    if (hasSibling) {
      if (siblingIndex >= siblingHashes.length) return false;
      const sibling = siblingHashes[siblingIndex++];
      currentHash = isRight
        ? computeNodeHash(sibling, currentHash)
        : computeNodeHash(currentHash, sibling);
    }

    currentIndex = Math.floor(currentIndex / 2);
    levelWidth = Math.ceil(levelWidth / 2);
  }

  return siblingIndex === siblingHashes.length && currentHash === expectedRoot;
}

/**
 * Compute Merkle root from an array of leaf hashes.
 * The reference construction of the tree `verifyInclusionProof` checks; the
 * verifier itself never builds one, and this is deliberately not exported.
 *
 * Odd cardinality: promote the final child unchanged.
 */
export function computeMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    throw new Error("Cannot compute Merkle root of empty leaf set");
  }
  if (leafHashes.length === 1) {
    return leafHashes[0];
  }

  let level = [...leafHashes];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const left = level[i];
      if (i + 1 < level.length) {
        next.push(computeNodeHash(left, level[i + 1]));
      } else {
        next.push(left);
      }
    }
    level = next;
  }
  return level[0];
}

/**
 * Generate sibling hashes (inclusion proof) for a leaf at a given index.
 * The reference construction of the proofs `verifyInclusionProof` checks; the
 * verifier itself never generates one, and this is deliberately not exported.
 */
export function generateInclusionProof(
  leafHashes: string[],
  leafIndex: number
): string[] {
  if (leafHashes.length <= 1) return [];

  const siblings: string[] = [];
  let level = [...leafHashes];

  let idx = leafIndex;
  while (level.length > 1) {
    const hasSibling = idx % 2 === 1 || idx + 1 < level.length;
    if (hasSibling) {
      const siblingIdx = idx % 2 === 0 ? idx + 1 : idx - 1;
      siblings.push(level[siblingIdx]);
    }
    // Move up
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(computeNodeHash(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    level = next;
    idx = Math.floor(idx / 2);
  }

  return siblings;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}
