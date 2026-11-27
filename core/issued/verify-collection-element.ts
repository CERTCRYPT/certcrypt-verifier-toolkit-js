/**
 * Element-level inclusion from the certificate alone (verifier-toolkit/1 §8.4.2).
 *
 * A `subject.collection/1` subject declares its leaves inside the signed
 * certificate (`subject.collection/1` §7.4), so holding the certificate and ONE
 * leaf value is enough to ask whether that value is one of the declared
 * elements: no inclusion-proof object, from anyone, is needed.
 *
 * The operation, in the order the specification fixes:
 *
 *  1. the certificate must be Issued-valid — the leaves are trustworthy only
 *     because they are signed;
 *  2. the declared leaves must fold to the declared `root`; a signed descriptor
 *     whose root does not reconstruct is internally inconsistent (`rejected`),
 *     which is not the same as the value being absent;
 *  3. the value's salted commitment is computed under EACH distinct profile the
 *     leaves declare — the caller never says which leaf it holds, and leaves
 *     may differ in profile;
 *  4. every position holding that commitment under that profile is a match,
 *     and each is confirmed through the §8.4.1 operation
 *     (`verifyCollectionInclusion`) over the sibling path derived for it.
 *
 * A value found nowhere is a negative outcome (`not_member`), not an error. A
 * value that repeats is reported at every position it occupies. A profile the
 * toolkit cannot canonicalize blocks a negative answer (`unsupported`) but not
 * a positive one: a match found under another declared profile stands.
 *
 * The result states membership of one declared element; it says nothing about
 * whether the collection is complete or its contents true.
 */

import type { BaseCertificate, SystemDomainConfig } from "../types/index.js";
import type { ResultCode } from "../types/result.js";
import { verify } from "../verify.js";
import {
  canonicalBytesForSubject,
  SUBJECT_COLLECTION,
  UnsupportedProfileError,
} from "../crypto/canonical-subject.js";
import {
  collectionLeafHash,
  collectionMerkleRoot,
  collectionNodeHash,
  verifyCollectionInclusion,
  COLLECTION_MERKLE_SCHEME,
} from "../crypto/collection-merkle.js";

export type CollectionElementOutcome =
  /** The value is a declared element at one or more positions. */
  | "member"
  /** Under every declared profile, the value is not a declared element. */
  | "not_member"
  /** The certificate is not Issued-valid, so its leaves prove nothing. */
  | "certificate_not_issued_valid"
  /** The certificate has no such collection, or its signed descriptor is inconsistent. */
  | "rejected"
  /** The scheme, or a declared leaf profile, is one this toolkit does not implement. */
  | "unsupported";

export interface CollectionElementMatch {
  /** Zero-based index of the collection subject in `anchor.subjects[]`. */
  subject_index: number;
  /** The declared leaf profile under which the value matched. */
  profile: string;
  /** Every leaf position holding the value under that profile, ascending. */
  leaf_indices: number[];
}

export interface CollectionElementResult {
  outcome: CollectionElementOutcome;
  matches: CollectionElementMatch[];
  /** What the Issued route returned for the certificate. */
  issued_result_code: ResultCode;
  /** Why the outcome is not `member` / `not_member`, or null. */
  reason: string | null;
}

export interface CollectionElementOptions {
  /** Restrict the search to one collection subject; all of them otherwise. */
  subjectIndex?: number;
  /** The configuration the certificate is verified under (the published one when omitted). */
  config?: SystemDomainConfig;
}

type Leaf = { profile: string; commitment_digest_hex: string };

/** Sibling path for one position of an ordered leaf-hash list (`collection.merkle-sha3-256/1`). */
function siblingPath(leafHashes: string[], leafIndex: number): string[] {
  const siblings: string[] = [];
  let level = leafHashes;
  let idx = leafIndex;
  while (level.length > 1) {
    // A lone right edge is promoted unchanged and contributes no sibling.
    const lone = idx === level.length - 1 && level.length % 2 === 1;
    if (!lone) siblings.push(idx % 2 === 0 ? level[idx + 1] : level[idx - 1]);
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? collectionNodeHash(level[i], level[i + 1]) : level[i]);
    }
    level = next;
    idx = Math.floor(idx / 2);
  }
  return siblings;
}

export function verifyCollectionElementFromCertificate(
  certificate: BaseCertificate,
  leafValue: Uint8Array,
  options: CollectionElementOptions = {},
): CollectionElementResult {
  const issued = verify(
    {
      verification_target_requested: "issued",
      input_mode: "artifact_set",
      base_certificate: certificate,
    },
    options.config,
  );
  const done = (
    outcome: CollectionElementOutcome,
    reason: string | null,
    matches: CollectionElementMatch[] = [],
  ): CollectionElementResult => ({
    outcome,
    matches,
    issued_result_code: issued.result_code,
    reason,
  });
  if (issued.result_code !== "ISSUED_VALID") {
    return done(
      "certificate_not_issued_valid",
      issued.failure_reason ?? `the certificate verifies as ${issued.result_code}`,
    );
  }
  if (!(leafValue instanceof Uint8Array)) {
    return done("rejected", "the leaf value must be bytes");
  }

  const anchor = certificate.payload.anchor;
  const salt = new TextEncoder().encode(anchor.nonce_hex);
  const subjects = anchor.subjects;
  const indices =
    options.subjectIndex === undefined
      ? subjects.map((_, i) => i).filter((i) => subjects[i].profile === SUBJECT_COLLECTION)
      : [options.subjectIndex];
  if (indices.length === 0) {
    return done("rejected", "the certificate declares no subject.collection/1 subject");
  }

  const matches: CollectionElementMatch[] = [];
  let unsupported: string | null = null;
  for (const si of indices) {
    const subject = subjects[si];
    if (!subject || subject.profile !== SUBJECT_COLLECTION || !subject.collection) {
      return done("rejected", `subject index ${si} is not a subject.collection/1 subject`);
    }
    const collection = subject.collection;
    if (collection.commitment_scheme !== COLLECTION_MERKLE_SCHEME) {
      unsupported = `subject index ${si}: commitment_scheme ${JSON.stringify(
        collection.commitment_scheme,
      )} is not supported`;
      continue;
    }
    const leaves = collection.leaves as Leaf[];
    const hashes = leaves.map((l) => l.commitment_digest_hex);
    // Step 1: the signed descriptor must reconstruct its own root.
    if (collectionMerkleRoot(hashes) !== collection.root) {
      return done(
        "rejected",
        `subject index ${si}: the declared leaves do not fold to the declared root`,
      );
    }

    const profiles = [...new Set(leaves.map((l) => l.profile))];
    for (const profile of profiles) {
      let canonical: Uint8Array;
      try {
        canonical = canonicalBytesForSubject(profile, leafValue);
      } catch (e) {
        if (e instanceof UnsupportedProfileError) {
          unsupported = `subject index ${si}: leaf profile ${profile} is not supported`;
        }
        // Bytes the profile cannot canonicalize are not an element under it.
        continue;
      }
      const own = collectionLeafHash(salt, profile, canonical);
      const at: number[] = [];
      leaves.forEach((l, li) => {
        if (l.profile === profile && l.commitment_digest_hex === own) at.push(li);
      });
      for (const li of at) {
        const check = verifyCollectionInclusion(
          salt,
          profile,
          canonical,
          {
            proof_version: COLLECTION_MERKLE_SCHEME,
            leaf_index: String(li),
            sibling_hashes: siblingPath(hashes, li),
          },
          collection.declared_cardinality,
          collection.root,
        );
        if (!check.valid) {
          return done("rejected", `subject index ${si}, leaf ${li}: ${check.reason}`);
        }
      }
      if (at.length > 0) matches.push({ subject_index: si, profile, leaf_indices: at });
    }
  }

  if (matches.length > 0) return done("member", null, matches);
  if (unsupported) return done("unsupported", unsupported);
  return done("not_member", null);
}
