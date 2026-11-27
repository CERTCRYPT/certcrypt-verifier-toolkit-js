/**
 * Merkle commitment scheme `collection.merkle-sha3-256/1` — the scheme that
 * hides the leaves of a `subject.collection/1` subject behind a single root.
 *
 * This is DISTINCT from the settlement Merkle in `merkle.ts`
 * (`settlement.aggregated.xrpl/1`, which prefixes 0x00 / 0x01). Do NOT substitute
 * one for the other — they have different leaf-preimage and node-preimage models
 * and would produce different roots. (verifier-toolkit/1.)
 *
 * Spec: collection.merkle-sha3-256/1.
 *   leaf_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:leaf")
 *     || u64be(len(collection_salt_bytes)) || collection_salt_bytes
 *     || u64be(len(leaf_profile_bytes)) || leaf_profile_bytes
 *     || u64be(len(leaf_canonical_bytes)) || leaf_canonical_bytes
 *   leaf_hash = SHA3-256(leaf_preimage)
 *   node_preimage = utf8("CERTCRYPT:collection.merkle-sha3-256/1:node")
 *     || left_hash || right_hash       (each 32 raw bytes)
 *   node_hash = SHA3-256(node_preimage)
 *   root: 1 leaf -> that leaf_hash; else pair left-to-right, promote a lone
 *   right-edge hash unchanged, until one remains. Empty tree is invalid.
 */

import { digestHexBytes } from "./digest.js";

// The VALUE declared in a collection's `commitment_scheme` field is the full
// scheme identifier `collection.merkle-sha3-256/1` — identical to the scheme's
// published identifier and document path, consistent with every other field
// identifier in the stack (`subject.binary/1`, `settlement.aggregated.xrpl/1`,
// `independence.proof/1`, …), so the value is resolvable to its spec. The same
// string is the domain-separation tag namespace below.
export const COLLECTION_MERKLE_SCHEME = "collection.merkle-sha3-256/1";

const LEAF_TAG = new TextEncoder().encode(
  "CERTCRYPT:collection.merkle-sha3-256/1:leaf",
);
const NODE_TAG = new TextEncoder().encode(
  "CERTCRYPT:collection.merkle-sha3-256/1:node",
);

/** 8-byte big-endian length prefix (u64be). */
function u64be(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) {
    throw new Error(`u64be requires a non-negative integer, got ${n}`);
  }
  const out = new Uint8Array(8);
  // JS numbers are safe integers up to 2^53; write the low 53 bits big-endian.
  let v = n;
  for (let i = 7; i >= 0; i--) {
    out[i] = v & 0xff;
    v = Math.floor(v / 256);
  }
  return out;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((s, p) => s + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex length must be even");
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error("invalid hex: non-hex characters present");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * leaf_hash for one leaf, given the collection salt, the declared `leaf_profile`
 * and the leaf's `canonical_bytes` (already produced under that profile).
 * Returns lowercase hex.
 *
 * The salt is bound into every leaf so that the same leaf set under a different
 * salt yields a different root (§9). Under `subject.collection/1` §8 the salt is
 * the certificate anchor's `nonce_hex` as ASCII bytes; this function takes it as
 * opaque bytes and MUST NOT interpret it.
 *
 * An empty salt is rejected: `/1` requires one, and silently accepting none would
 * reproduce the unsalted construction whose leaf hashes are stable global
 * identifiers of content.
 */
export function collectionLeafHash(
  collectionSalt: Uint8Array,
  leafProfile: string,
  leafCanonicalBytes: Uint8Array,
): string {
  if (collectionSalt.length === 0) {
    throw new Error(
      "collection.merkle-sha3-256/1: a non-empty collection salt is required (§9)",
    );
  }
  const leafProfileBytes = new TextEncoder().encode(leafProfile);
  const preimage = concat(
    LEAF_TAG,
    u64be(collectionSalt.length),
    collectionSalt,
    u64be(leafProfileBytes.length),
    leafProfileBytes,
    u64be(leafCanonicalBytes.length),
    leafCanonicalBytes,
  );
  return digestHexBytes(preimage);
}

/** node_hash for two child hashes (lowercase hex in, lowercase hex out). */
export function collectionNodeHash(leftHex: string, rightHex: string): string {
  const preimage = concat(NODE_TAG, hexToBytes(leftHex), hexToBytes(rightHex));
  return digestHexBytes(preimage);
}

/**
 * Compute the collection root from an ordered list of leaf hashes (lowercase
 * hex). Rule: single leaf -> its hash; else pair left-to-right and
 * promote a lone right-edge hash unchanged until one remains. Throws on empty
 * (empty-tree prohibition).
 */
export function collectionMerkleRoot(leafHashes: string[]): string {
  if (leafHashes.length === 0) {
    throw new Error("collection.merkle-sha3-256/1: empty tree is invalid");
  }
  let level = leafHashes;
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(collectionNodeHash(level[i], level[i + 1]));
      } else {
        next.push(level[i]); // promote lone right-edge hash unchanged
      }
    }
    level = next;
  }
  return level[0];
}

const HEX64_RE = /^[0-9a-f]{64}$/;
const CANONICAL_UINT_RE = /^(0|[1-9][0-9]*)$/;

/**
 * The logical inclusion-proof object of `collection.merkle-sha3-256/1` — the
 * exact three members, no more. `leaf_index` and `proof_version` are
 * strings because that is how the scheme serializes them; `sibling_hashes` are lowercase
 * hex digests in bottom-up order. verifyCollectionInclusion enforces all of it,
 * including the absence of any additional member, so parsed JSON can be passed
 * as is.
 */
export interface CollectionInclusionProof {
  proof_version: string;
  leaf_index: string;
  sibling_hashes: string[];
}

/** Outcome of a `collection.merkle-sha3-256/1` element inclusion check. `valid`
 *  is true only when the leaf provably belongs to the declared root; otherwise
 *  `reason` names the failure condition that fired. Fail-closed: any malformed
 *  input yields `valid: false`, never a throw for adversary-controlled proof data. */
export interface CollectionInclusionResult {
  valid: boolean;
  reason: string | null;
}

const ok: CollectionInclusionResult = { valid: true, reason: null };
function reject(reason: string): CollectionInclusionResult {
  return { valid: false, reason };
}

/**
 * Verify that ONE declared leaf belongs to a `subject.collection/1` root under
 * `collection.merkle-sha3-256/1`, given only that leaf, its inclusion path, and
 * the declared root — WITHOUT supplying the rest of the collection. This is the
 * element-level inclusion capacity of the scheme, distinct from and NOT built on
 * `verify-original-material.ts`, which needs the full ordered leaf set and rebuilds
 * the whole root.
 *
 * Pure and fail-closed: adversary-controlled `proof`/`declaredRoot` never throw;
 * any malformed or non-matching input returns `{valid:false, reason}`.
 *
 * The fold reproduces the specified procedure exactly, so a positive result reconstructs the SAME root
 * `collectionMerkleRoot` would compute over the full ordered leaf set — verified by
 * the shared conformance vectors (fixtures/primitives/collection-merkle).
 *
 * @param collectionSalt       the collection salt (subject.collection/1 §8: the
 *                             anchor `nonce_hex` as ASCII bytes)
 * @param leafProfile          declared `leaf_profile` of the collection subject
 * @param leafCanonicalBytes   canonical_bytes of the leaf being proven, under that profile
 * @param proof                the inclusion-proof object for this leaf
 * @param declaredCardinality  the collection's `declared_cardinality` (canonical uint string)
 * @param declaredRoot         the collection subject's declared `root` (64-char lowercase hex)
 */
export function verifyCollectionInclusion(
  collectionSalt: Uint8Array,
  leafProfile: string,
  leafCanonicalBytes: Uint8Array,
  proof: CollectionInclusionProof,
  declaredCardinality: string,
  declaredRoot: string,
): CollectionInclusionResult {
  // A salt is required (§9, §16). Rejected rather than thrown: this entry point is
  // fail-closed for adversary-controlled material.
  if (!(collectionSalt instanceof Uint8Array) || collectionSalt.length === 0) {
    return reject("collection salt is missing or empty");
  }
  // declared root must be a 64-char lowercase hex string.
  if (typeof declaredRoot !== "string" || !HEX64_RE.test(declaredRoot)) {
    return reject("declared root is not a 64-char lowercase hex string");
  }
  // declared_cardinality must parse as a positive integer.
  if (typeof declaredCardinality !== "string" || !CANONICAL_UINT_RE.test(declaredCardinality)) {
    return reject("declared_cardinality is not a canonical unsigned integer string");
  }
  const n = Number(declaredCardinality);
  if (n < 1 || !Number.isSafeInteger(n)) {
    return reject("declared_cardinality out of range (empty tree prohibited)");
  }

  // exactly the three members of the proof object; an additional one fails.
  if (proof === null || typeof proof !== "object" || Array.isArray(proof)) {
    return reject("inclusion proof is not an object");
  }
  const members = Object.keys(proof).sort();
  if (
    members.length !== 3 ||
    members[0] !== "leaf_index" ||
    members[1] !== "proof_version" ||
    members[2] !== "sibling_hashes"
  ) {
    return reject("inclusion proof members are not exactly proof_version, leaf_index, sibling_hashes");
  }
  // proof_version must be exactly the scheme identifier.
  if (proof.proof_version !== COLLECTION_MERKLE_SCHEME) {
    return reject(`proof_version differs (expected ${COLLECTION_MERKLE_SCHEME})`);
  }
  // leaf_index must be a canonical unsigned base-10 integer string.
  if (typeof proof.leaf_index !== "string" || !CANONICAL_UINT_RE.test(proof.leaf_index)) {
    return reject("leaf_index missing or non-canonical");
  }
  const i = Number(proof.leaf_index);
  if (!Number.isSafeInteger(i)) {
    return reject("leaf_index out of representable range");
  }
  // reject if i >= N.
  if (i >= n) {
    return reject(`leaf_index ${i} out of bounds for declared_cardinality ${n}`);
  }
  // sibling_hashes must be an array of 64-char lowercase hex strings.
  if (!Array.isArray(proof.sibling_hashes)) {
    return reject("sibling_hashes is not an array");
  }
  for (const s of proof.sibling_hashes) {
    if (typeof s !== "string" || !HEX64_RE.test(s)) {
      return reject("sibling_hashes contains a malformed entry (not 64-char lowercase hex)");
    }
  }

  // compute the leaf hash of the leaf being proven.
  let currentHash: string;
  try {
    currentHash = collectionLeafHash(collectionSalt, leafProfile, leafCanonicalBytes);
  } catch (e) {
    return reject(`leaf canonicalization error: ${(e as Error).message}`);
  }

  // fold upward. A lone rightmost node on an odd-width level is promoted
  // unchanged and consumes NO sibling (promotion rule) — so the proof carries exactly
  // one sibling per level at which the current node HAS a sibling, and no more.
  let currentIndex = i;
  let currentWidth = n;
  let cursor = 0;
  while (currentWidth > 1) {
    const isLoneRightmost = currentWidth % 2 === 1 && currentIndex === currentWidth - 1;
    if (!isLoneRightmost) {
      if (cursor >= proof.sibling_hashes.length) {
        return reject("too few sibling hashes for the tree shape");
      }
      const sibling = proof.sibling_hashes[cursor++];
      currentHash =
        currentIndex % 2 === 0
          ? collectionNodeHash(currentHash, sibling) // even -> node(current, sibling)
          : collectionNodeHash(sibling, currentHash); // odd  -> node(sibling, current)
    }
    // else: promoted unchanged, no sibling consumed.
    currentIndex = Math.floor(currentIndex / 2);
    currentWidth = Math.ceil(currentWidth / 2);
  }

  // every supplied sibling MUST have been consumed — no extras.
  if (cursor !== proof.sibling_hashes.length) {
    return reject("too many sibling hashes for the tree shape");
  }
  // accept only if the recomputed root equals the declared root.
  if (currentHash !== declaredRoot) {
    return reject("recomputed root differs from declared root");
  }
  return ok;
}
