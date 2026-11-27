/**
 * Complete verification against original material (verifier-toolkit/1).
 *
 * Given the certificate's committed subjects and the
 * verifier-local subject-material map, recompute each subject's
 * `canonical_bytes` under its declared profile, derive the verifier-local
 * `subject_local_digest_hex`, rebuild the CCCP/1 commitment with the anchor
 * nonce, and require it to equal the certificate's `commitment_digest_hex`. For
 * `subject.collection/1` subjects, also reconstruct the collection root and
 * require the leaf count to equal `declared_cardinality` (verifier-toolkit/1
 * §8.5.3). For `subject.ai-decision/1` subjects delivered with disclosed parts,
 * also compare each by id against the salted commitment the matched record declares.
 *
 * This is opt-in: it runs only when a subject-material map is supplied. With no
 * material, the toolkit reports `ORIGINAL_MATERIAL_COMPARISON_VALID` as not
 * performed (a separate verification plane). Outcomes for a supplied but
 * non-conformant delivery are fixed by the profile so toolkits converge.
 *
 * Privacy: `subject_local_digest_hex` is verifier-local and MUST NOT be
 * surfaced; this module never returns or logs it.
 */

import type {
  AiDecisionMaterial,
  BaseCertificate,
  SubjectMaterialMap,
  PrehashedMaterial,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";
import {
  canonicalBytesForSubject,
  UnsupportedProfileError,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
  isOpaqueByteProfile,
  OPAQUE_BYTE_PROFILES,
} from "../crypto/canonical-subject.js";

/**
 * A material entry the caller hashed itself, rather than the bytes.
 *
 * Structural, not nominal: the map is verifier-local and may cross a bundler boundary, so
 * this tests the discriminant rather than trusting a class identity.
 */
function isPrehashed(
  entry: unknown,
): entry is PrehashedMaterial {
  return (
    typeof entry === "object" &&
    entry !== null &&
    !(entry instanceof Uint8Array) &&
    (entry as { prehashed?: unknown }).prehashed === true
  );
}
/** An AI-decision record delivered together with its input and/or output material. */
function isAiDecisionMaterial(entry: unknown): entry is AiDecisionMaterial {
  return (
    typeof entry === "object" &&
    entry !== null &&
    !(entry instanceof Uint8Array) &&
    (entry as { record?: unknown }).record instanceof Uint8Array
  );
}
import { jcsCanonicalizeBytes, jcsCanonicalizeString } from "../crypto/jcs.js";
import {
  collectionLeafHash,
  collectionMerkleRoot,
  COLLECTION_MERKLE_SCHEME,
} from "../crypto/collection-merkle.js";

const HEX64_RE = /^[0-9a-f]{64}$/;

/**
 * Verify the certificate's subjects against the supplied original material.
 *
 * `material` maps the zero-based subject index (as in
 * `anchor.subjects[]`) to that subject's bytes. For a `subject.collection/1`
 * subject the entry is the ORDERED list of leaf materials; for any other
 * profile it is the single subject's bytes.
 */
export function verifyOriginalMaterial(
  cert: BaseCertificate,
  material: SubjectMaterialMap | null,
  builder: ResultBuilder,
  /** The subject profiles the rules domain admits; a collection leaf declaring
   *  any other fails closed (REJECTED), not as merely unsupported. */
  admittedProfiles: readonly string[],
): void {
  // Opt-in plane: no material supplied → not performed. The structural
  // Independent/Issued result stands on its own; this is a separate plane.
  if (!material) {
    builder.addDiagnostic(
      "info",
      "original material not supplied; complete verification against material not performed",
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
    );
    return;
  }

  // Material WAS delivered → the complete-verification plane runs. Mark it
  // performed now; passed becomes true only if every subject matches (set at the
  // end). Any fail() below leaves performed=true, passed=false — an honest
  // "ran and did not match", distinct from the default "not performed".
  builder.setCompleteMaterialResult(true, false);

  const anchor = cert.payload?.anchor;
  const subjects = anchor?.subjects;
  const nonceHex = anchor?.nonce_hex;
  if (!Array.isArray(subjects) || subjects.length === 0 || !nonceHex) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      "cannot verify material: certificate anchor has no subjects or nonce",
    );
    return;
  }

  const missingIndices: number[] = [];
  for (let i = 0; i < subjects.length; i++) {
    if (material.get(i) === undefined) missingIndices.push(i);
  }
  if (missingIndices.length > 0) {
    const list = missingIndices.join(", ");
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "INCOMPLETE",
      missingIndices.length === 1
        ? `original material missing for subject index ${list}`
        : `original material missing for ${missingIndices.length} of ${subjects.length} subjects (indices ${list})`,
    );
    return;
  }

  // §8.5.1: the certificate alone fixes cardinality and order. A delivery that
  // keys anything other than an index 0..N-1 adds a subject the certificate does
  // not declare, and is REJECTED rather than ignored.
  const strayKeys = [...material.keys()].filter(
    (k) => !Number.isInteger(k) || k < 0 || k >= subjects.length,
  );
  if (strayKeys.length > 0) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `original material delivered for subject index ${strayKeys.map(String).join(", ")}, ` +
        `but the certificate declares ${subjects.length} subject(s) (indices 0..${subjects.length - 1})`,
    );
    return;
  }

  for (let i = 0; i < subjects.length; i++) {
    const subject = subjects[i];
    let entry = material.get(i)!;

    // Nested part material exists only for an AI-decision subject. For any
    // other profile it is material the certificate does not commit to.
    let aiNested: AiDecisionMaterial | null = null;
    if (isAiDecisionMaterial(entry)) {
      if (subject.profile !== SUBJECT_AI_DECISION) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          "REJECTED",
          `subject index ${i}: nested material delivered for a ${subject.profile} ` +
            `subject; only a ${SUBJECT_AI_DECISION} subject has any`,
        );
        return;
      }
      aiNested = entry;
      entry = entry.record;
    }

    let canonicalBytes: Uint8Array;
    try {
      if (subject.profile === SUBJECT_COLLECTION && !isPrehashed(entry)) {
        // Entry is the ordered leaf-material list; the per-subject canonical
        // bytes is the collection JSON object itself, recomputed below from the
        // committed root + cardinality. For a collection, the certificate's
        // subject commitment is over the collection object's canonical bytes,
        // and the collection object carries the root the leaves reconstruct.
        const verdict = verifyCollectionSubject(
          subject,
          entry,
          builder,
          i,
          new TextEncoder().encode(nonceHex),
          admittedProfiles,
        );
        if (!verdict) return;
        canonicalBytes = verdict;
      } else if (isPrehashed(entry)) {
        // The caller streamed the material and kept only its digest — the browser path for
        // a file too large to hold in one ArrayBuffer. Accepted for `subject.binary/1`
        // ONLY, where canonical_bytes IS the input bytes, so a chunked digest equals a
        // whole-buffer one. For every other profile canonicalization rewrites the material
        // before hashing (line endings, header unfolding, JCS over the parsed value) and a
        // digest of the raw bytes is simply a DIFFERENT value; taking it would report a
        // material mismatch when the real fault is the caller's.
        if (!isOpaqueByteProfile(subject.profile)) {
          builder.fail(
            "ORIGINAL_MATERIAL_COMPARISON_VALID",
            "REJECTED",
            `subject index ${i}: a prehashed digest is only valid for a profile whose ` +
              `canonical_bytes are the input bytes (${OPAQUE_BYTE_PROFILES.join(", ")}), ` +
              `not ${subject.profile} — that profile canonicalizes the material before hashing`,
          );
          return;
        }
        if (!/^[0-9a-f]{64}$/.test(entry.subject_local_digest_hex)) {
          builder.fail(
            "ORIGINAL_MATERIAL_COMPARISON_VALID",
            "REJECTED",
            `subject index ${i}: prehashed subject_local_digest_hex must be 64 lowercase hex characters`,
          );
          return;
        }
        // Same two lines as the byte path below, minus the digest we already hold.
        const recomputedPrehashed = digestHexText(
          nonceHex + entry.subject_local_digest_hex,
        );
        if (recomputedPrehashed !== subject.commitment_digest_hex) {
          builder.fail(
            "ORIGINAL_MATERIAL_COMPARISON_VALID",
            "ISSUED_INVALID",
            `subject index ${i}: material does not match the committed subject ` +
              `(recomputed commitment != certificate commitment_digest_hex)`,
          );
          return;
        }
        continue;
      } else {
        if (!(entry instanceof Uint8Array)) {
          builder.fail(
            "ORIGINAL_MATERIAL_COMPARISON_VALID",
            "REJECTED",
            `subject index ${i} (${subject.profile}) expects single-material bytes, got a leaf list`,
          );
          return;
        }
        canonicalBytes = canonicalBytesForSubject(subject.profile, entry);
      }
    } catch (e) {
      if (e instanceof UnsupportedProfileError) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          "UNSUPPORTED",
          `subject index ${i}: ${e.message}`,
        );
        return;
      }
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "REJECTED",
        `subject index ${i}: canonicalization error: ${(e as Error).message}`,
      );
      return;
    }

    // CCCP/1: commitment = SHA3-256(ASCII(nonce_hex) || ASCII(subject_local_digest_hex)).
    const subjectLocalDigestHex = digestHexBytes(canonicalBytes);
    const recomputed = digestHexText(nonceHex + subjectLocalDigestHex);
    if (recomputed !== subject.commitment_digest_hex) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "ISSUED_INVALID",
        `subject index ${i}: material does not match the committed subject ` +
          `(recomputed commitment != certificate commitment_digest_hex)`,
      );
      return;
    }

    if (aiNested && !verifyAiDecisionMaterials(canonicalBytes, aiNested, builder, i)) return;
  }

  builder.pass("ORIGINAL_MATERIAL_COMPARISON_VALID");
  // The complete-verification-against-material plane actually ran and matched
  // every delivered subject; reflect it so the result distinguishes
  // "material verified" from the default "not performed".
  builder.setCompleteMaterialResult(true, true);
}

/**
 * Compare disclosed AI-decision parts by record-local id with the salted
 * commitments the matched record declares.
 *
 * Runs only after the record has matched the certificate's commitment, so `profile` and
 * `material_nonce_hex` and `commitment_digest_hex` are read from the committed record —
 * never from the delivery. Each part is optional; an omitted part is not compared.
 *
 * Returns false after recording a failure.
 */
function verifyAiDecisionMaterials(
  recordCanonicalBytes: Uint8Array,
  nested: AiDecisionMaterial,
  builder: ResultBuilder,
  index: number,
): boolean {
  const record = JSON.parse(new TextDecoder().decode(recordCanonicalBytes)) as {
    input: { id: string; profile: string; material_nonce_hex: string; commitment_digest_hex: string }[];
    output: { id: string; profile: string; material_nonce_hex: string; commitment_digest_hex: string }[];
  };
  const declared = new Map(
    [...record.input, ...record.output].map((part) => [part.id, part] as const),
  );
  if (!(nested.materials instanceof Map)) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: AI-decision materials must be a Map keyed by part id`,
    );
    return false;
  }
  for (const id of nested.materials.keys()) {
    if (!declared.has(id)) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "REJECTED",
        `subject index ${index}: material delivered for unknown AI-decision part id ${JSON.stringify(id)}`,
      );
      return false;
    }
  }
  for (const [id, delivered] of nested.materials) {
    const { profile, material_nonce_hex, commitment_digest_hex } = declared.get(id)!;
    let subjectLocalDigestHex: string;
    if (isPrehashed(delivered)) {
      if (!isOpaqueByteProfile(profile)) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          "REJECTED",
          `subject index ${index}: prehashed material for part ${JSON.stringify(id)} is only valid under subject.binary/1`,
        );
        return false;
      }
      if (!HEX64_RE.test(delivered.subject_local_digest_hex)) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          "REJECTED",
          `subject index ${index}: prehashed digest for part ${JSON.stringify(id)} must be 64 lowercase hex characters`,
        );
        return false;
      }
      subjectLocalDigestHex = delivered.subject_local_digest_hex;
    } else {
      if (!(delivered instanceof Uint8Array)) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          "REJECTED",
          `subject index ${index}: material for part ${JSON.stringify(id)} must be bytes or a prehashed binary digest`,
        );
        return false;
      }
      try {
        subjectLocalDigestHex = digestHexBytes(canonicalBytesForSubject(profile, delivered));
      } catch (e) {
        builder.fail(
          "ORIGINAL_MATERIAL_COMPARISON_VALID",
          e instanceof UnsupportedProfileError ? "UNSUPPORTED" : "REJECTED",
          `subject index ${index}: material for part ${JSON.stringify(id)} under ${profile}: ${(e as Error).message}`,
        );
        return false;
      }
    }
    const recomputedCommitment = digestHexText(material_nonce_hex + subjectLocalDigestHex);
    if (recomputedCommitment !== commitment_digest_hex) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "ISSUED_INVALID",
        `subject index ${index}: material for part ${JSON.stringify(id)} does not match the record's commitment_digest_hex ` +
          `(recomputed under ${profile})`,
      );
      return false;
    }
  }
  return true;
}

/**
 * For a `subject.collection/1` subject, the descriptor is read from the SIGNED
 * certificate (`subjects[i].collection`), never from the delivered material.
 *
 * That is why the descriptor lives inside the subject: each leaf's `profile`
 * decides how that leaf canonicalizes and enters its hash preimage, so a profile
 * taken from unsigned delivery would let a DIFFERENT file be declared under a
 * profile that canonicalizes to the committed bytes.
 *
 * The delivery therefore supplies the ordered leaf bytes. An optional `collection`
 * member may accompany them; when present it MUST be canonically identical to the
 * signed descriptor, so a stale copy fails loudly instead of silently overriding
 * the signed one.
 *
 * Returns the canonical bytes of the collection descriptor (for the outer CCCP
 * commitment) on success, or null after recording a failure.
 */
function verifyCollectionSubject(
  subject: { profile: string; commitment_digest_hex: string; collection?: unknown },
  leafEntry: Uint8Array | Uint8Array[] | { collection?: unknown; leaves: Uint8Array[] },
  builder: ResultBuilder,
  index: number,
  /** subject.collection/1 §8: the anchor `nonce_hex` as ASCII bytes. Taken from the
   *  certificate under verification, NEVER from the delivered material. */
  collectionSalt: Uint8Array,
  admittedProfiles: readonly string[],
): Uint8Array | null {
  // The descriptor comes from the signed subject. No descriptor, no verification:
  // there is nothing to check the leaves against.
  const collection = subject.collection as Record<string, unknown> | undefined;
  if (collection === undefined || collection === null || typeof collection !== "object" || Array.isArray(collection)) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: the signed subject carries no \`collection\` descriptor ` +
        `(subject.collection/1 §7)`,
    );
    return null;
  }

  // The delivery supplies the ordered leaf bytes.
  if (
    leafEntry instanceof Uint8Array ||
    Array.isArray(leafEntry) ||
    typeof leafEntry !== "object" ||
    !("leaves" in leafEntry)
  ) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection material must be { leaves[] }`,
    );
    return null;
  }

  const leaves = leafEntry.leaves;
  if (!Array.isArray(leaves)) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection leaves must be an array`,
    );
    return null;
  }

  // subject.collection/1 §7: EXACTLY these 4 members, no additional ones. Reject
  // malformed structure up front (REJECTED) rather than letting it surface later as
  // a commitment mismatch — extra members would change the JCS and only fail
  // downstream.
  const COLLECTION_FIELDS = ["commitment_scheme", "root", "declared_cardinality", "leaves"];
  const keys = Object.keys(collection);
  if (
    keys.length !== COLLECTION_FIELDS.length ||
    !COLLECTION_FIELDS.every((f) => Object.prototype.hasOwnProperty.call(collection, f))
  ) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection descriptor must contain exactly ` +
        `{commitment_scheme, root, declared_cardinality, leaves} (subject.collection/1)`,
    );
    return null;
  }

  const scheme = collection.commitment_scheme;
  const root = collection.root;
  const declaredCardinalityStr = collection.declared_cardinality;
  const declaredLeaves = collection.leaves;

  if (scheme !== COLLECTION_MERKLE_SCHEME) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "UNSUPPORTED",
      `subject index ${index}: unsupported collection commitment_scheme ${JSON.stringify(scheme)}`,
    );
    return null;
  }
  if (typeof root !== "string" || !HEX64_RE.test(root)) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection root is not a 64-char lowercase hex string`,
    );
    return null;
  }
  // Each entry declares its own profile and commitment (§7.4).
  if (!Array.isArray(declaredLeaves) || declaredLeaves.length === 0) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection leaves[] must be a non-empty array`,
    );
    return null;
  }
  const leafProfiles: string[] = [];
  const leafCommitments: string[] = [];
  for (let li = 0; li < declaredLeaves.length; li++) {
    const leaf = declaredLeaves[li] as Record<string, unknown> | null;
    if (typeof leaf !== "object" || leaf === null || Array.isArray(leaf)) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "REJECTED",
        `subject index ${index}: leaves[${li}] must be an object`,
      );
      return null;
    }
    const lk = Object.keys(leaf);
    if (
      lk.length !== 2 ||
      typeof leaf.profile !== "string" ||
      typeof leaf.commitment_digest_hex !== "string" ||
      !HEX64_RE.test(leaf.commitment_digest_hex)
    ) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "REJECTED",
        `subject index ${index}: leaves[${li}] must be ` +
          `{profile, commitment_digest_hex} with a 64-char lowercase hex commitment`,
      );
      return null;
    }
    leafProfiles.push(leaf.profile);
    leafCommitments.push(leaf.commitment_digest_hex);
  }
  // declared_cardinality is a canonical unsigned-integer string (subject.collection/1).
  if (typeof declaredCardinalityStr !== "string" || !/^[1-9][0-9]*$/.test(declaredCardinalityStr)) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: declared_cardinality must be a canonical positive integer string`,
    );
    return null;
  }
  const declaredCardinality = Number(declaredCardinalityStr);
  // §7.4.3: the economic layer reads declared_cardinality, so it MUST agree with
  // the array rather than be derived from it.
  if (declaredLeaves.length !== declaredCardinality) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: leaves[] length ${declaredLeaves.length} != ` +
        `declared_cardinality ${declaredCardinality}`,
    );
    return null;
  }

  // A delivered copy of the descriptor is tolerated but must not disagree with the
  // signed one. Compared canonically so key order is irrelevant.
  if (leafEntry.collection !== undefined) {
    const signedCanon = jcsCanonicalizeString(collection);
    let deliveredCanon: string;
    try {
      deliveredCanon = jcsCanonicalizeString(leafEntry.collection);
    } catch {
      deliveredCanon = "";
    }
    if (deliveredCanon !== signedCanon) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "REJECTED",
        `subject index ${index}: the delivered collection descriptor does not match ` +
          `the one signed in the certificate`,
      );
      return null;
    }
  }

  // Empty tree prohibited — declared_cardinality is already > 0 by regex,
  // but the delivered leaf set could still be empty.
  if (leaves.length === 0) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: collection delivered with zero leaves (empty tree invalid)`,
    );
    return null;
  }

  // Count of leaf materials that participate in the root MUST equal declared_cardinality.
  if (leaves.length !== declaredCardinality) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: leaf count ${leaves.length} != declared_cardinality ${declaredCardinality}`,
    );
    return null;
  }

  // Every leaf profile must be one the rules domain admits. Checked before any
  // leaf is canonicalized, so a non-admitted profile is REJECTED as
  // non-conformant rather than surfacing as UNSUPPORTED.
  const notAdmitted = leafProfiles
    .map((profile, li) => ({ li, profile }))
    .filter(({ profile }) => !admittedProfiles.includes(profile));
  if (notAdmitted.length > 0) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: leaf profile not admitted by the rules domain: ` +
        notAdmitted.map(({ li, profile }) => `leaves[${li}].profile=${profile}`).join("; "),
    );
    return null;
  }

  // Reconstruct each leaf hash under ITS OWN declared profile.
  let leafHashes: string[];
  try {
    leafHashes = leaves.map((leafBytes, li) =>
      collectionLeafHash(
        collectionSalt,
        leafProfiles[li],
        canonicalBytesForSubject(leafProfiles[li], leafBytes),
      ),
    );
  } catch (e) {
    if (e instanceof UnsupportedProfileError) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "UNSUPPORTED",
        `subject index ${index}: leaf ${e.message}`,
      );
      return null;
    }
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "REJECTED",
      `subject index ${index}: leaf canonicalization error: ${(e as Error).message}`,
    );
    return null;
  }

  // Each recomputed hash MUST equal the commitment the certificate signed for that
  // leaf. This localizes the failure to a leaf index instead of reporting only a
  // root mismatch, and it is what makes `leaves[]` verifiable rather than decorative.
  for (let li = 0; li < leafHashes.length; li++) {
    if (leafHashes[li] !== leafCommitments[li]) {
      builder.fail(
        "ORIGINAL_MATERIAL_COMPARISON_VALID",
        "ISSUED_INVALID",
        `subject index ${index}: leaf ${li} does not match its signed commitment`,
      );
      return null;
    }
  }

  const recomputedRoot = collectionMerkleRoot(leafHashes);
  if (recomputedRoot !== root) {
    builder.fail(
      "ORIGINAL_MATERIAL_COMPARISON_VALID",
      "ISSUED_INVALID",
      `subject index ${index}: recomputed collection root != declared root`,
    );
    return null;
  }

  // The subject's CCCP commitment is over the canonical bytes of the collection
  // descriptor (subject.collection/1 = JCS of the object).
  return canonicalBytesForSubject(SUBJECT_COLLECTION, jcsCanonicalizeBytes(collection));
}
