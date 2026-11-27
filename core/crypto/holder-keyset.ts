/**
 * Membership of one disclosed operation key in a `holder_key_set_root`, under
 * `holder-keyset.merkle-sha3-256/1` (§11 disclosure, §12 procedure, §13 failure
 * conditions).
 *
 * The disclosure arrives inside adversary-controlled evidence, so it is checked
 * as parsed JSON, not trusted as a typed object: exactly four members, integers
 * that are JSON integers, canonical base64, lowercase hex. Fail-closed and
 * never throws.
 *
 * A positive result proves membership only. It is not an identity: `tree_size`
 * is not committed to by the root, and no signature covers the disclosure, so
 * two disclosures with different bytes can prove the same membership.
 */

import { computeLeafHash, verifyInclusionProof } from "./merkle.js";
import { strictBase64Decode } from "./provider/bytes.js";

const DISCLOSURE_MEMBERS = ["inclusion_proof", "leaf_index", "public_key_b64", "tree_size"];

export interface DisclosureVerdict {
  valid: boolean;
  reason: string | null;
}

function reject(reason: string): DisclosureVerdict {
  return { valid: false, reason };
}

/**
 * @param disclosure the `operation_key` object of a `capacity.evidence/1`
 * @param root       the authorized `holder_key_set_root` (64-char lowercase hex)
 */
export function verifyOperationKeyDisclosure(disclosure: unknown, root: string): DisclosureVerdict {
  if (disclosure === null || typeof disclosure !== "object" || Array.isArray(disclosure)) {
    return reject("disclosure is not a JSON object");
  }
  const d = disclosure as Record<string, unknown>;
  const keys = Object.keys(d).sort();
  if (keys.length !== DISCLOSURE_MEMBERS.length || keys.some((k, i) => k !== DISCLOSURE_MEMBERS[i])) {
    return reject("disclosure members are not exactly leaf_index, public_key_b64, inclusion_proof, tree_size");
  }
  const n = d.tree_size;
  const i = d.leaf_index;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < 1) {
    return reject("tree_size is not a positive JSON integer");
  }
  if (typeof i !== "number" || !Number.isSafeInteger(i) || i < 0) {
    return reject("leaf_index is not a non-negative JSON integer");
  }
  if (i >= n) {
    return reject("leaf_index >= tree_size");
  }
  if (typeof d.public_key_b64 !== "string") {
    return reject("public_key_b64 is not a string");
  }
  let pk: Uint8Array;
  try {
    pk = strictBase64Decode(d.public_key_b64, "public_key_b64");
  } catch {
    return reject("public_key_b64 is not canonical base64");
  }
  const proof = d.inclusion_proof;
  if (!Array.isArray(proof) || !proof.every((h) => typeof h === "string" && /^[0-9a-f]{64}$/.test(h))) {
    return reject("an inclusion_proof entry is not 64-char lowercase hex");
  }
  if (!verifyInclusionProof(computeLeafHash(pk), i, proof as string[], root, n)) {
    return reject("the inclusion proof does not bind the key to the root");
  }
  return { valid: true, reason: null };
}
