import type {
  BaseCertificate,
  IndependenceProof,
  SystemDomainConfig,
  VerifierRequest,
  VerifierResult,
} from "../types/index.js";
import { verify } from "../verify.js";
import { PENDING_CORPUS_PROOF } from "../config/default.js";
import { collectionLeafHash, collectionMerkleRoot } from "../crypto/collection-merkle.js";
import { canonicalBytesForSubject } from "../crypto/canonical-subject.js";
import { loadArtifacts } from "../input/load-artifacts.js";

const COLLECTION_PROFILE = "subject.collection/1";
const TEXT_PROFILE = "subject.text/1";
const BINARY_PROFILE = "subject.binary/1";

/** One document of a rules domain, in the order its corpus proof certifies it. */
export interface RulesCorpusDocument {
  /** Where the document was read from. Reported, never committed: the leaf binds content and order. */
  path?: string;
  bytes: Uint8Array;
}

export interface RulesCorpusResult {
  /** True only when every link of the chain holds. */
  valid: boolean;
  /** One line per broken link, in the order they were checked. Empty when valid. */
  failures: string[];
  rules_version: string | null;
  /** The corpus proof's anchored `subtree_root` — the value a conforming verifier carries. */
  subtree_root: string | null;
  /** The collection root the corpus certificate signs over the documents. */
  collection_root: string | null;
  declared_cardinality: number | null;
  /** The ordinary verdict on the corpus proof itself. */
  verdict: VerifierResult;
}

/**
 * Establish that a set of documents is the exact ruleset a corpus proof certifies
 * (`rules-domain/1` §13.3), without a live CERTCRYPT service and without trusting
 * where the documents or the proof came from.
 *
 * The chain, link by link:
 *
 * 1. The corpus proof verifies as an ordinary proof: `INDEPENDENT_VALID` under
 *    `config`, for the `rules_version` it certifies.
 * 2. Its anchored `subtree_root` is the commitment `config` carries for that
 *    `rules_version`. That pins the one proof: a second emission over the same text
 *    has another `subtree_root` and does not pass (§13.3.2; `independence.proof/1`
 *    §12.9).
 * 3. Its certificate commits to exactly one `subject.collection/1` whose leaves are
 *    all `subject.text/1`, as many as the documents supplied.
 * 4. Each document, canonicalized under `subject.text/1` and salted with the
 *    certificate's anchor `nonce_hex` (`subject.collection/1` §8), reproduces its
 *    leaf, and the leaves fold to the signed collection root.
 *
 * Link 4 is what binds the text; links 1–2 are what make that binding the one the
 * verifier trusts. Establishing authenticity of the text says nothing about whether
 * the rules are right — only that they are the ones that govern.
 */
export function verifyRulesCorpus(
  request: VerifierRequest,
  documents: RulesCorpusDocument[],
  config: SystemDomainConfig,
): RulesCorpusResult {
  const failures: string[] = [];
  const verdict = verify(request, config);
  const { baseCertificate, independenceProof } = loadArtifacts(request) as {
    baseCertificate: BaseCertificate | null;
    independenceProof: IndependenceProof | null;
  };

  const rulesVersion = independenceProof?.rules_version ?? null;
  const subtreeRoot = independenceProof?.subtree_root ?? null;

  // 1. The proof itself.
  if (verdict.result_code !== "INDEPENDENT_VALID") {
    failures.push(
      `the corpus proof does not verify as independent: ${verdict.result_code}` +
        (verdict.failure_reason ? ` — ${verdict.failure_reason}` : ""),
    );
  }
  if (rulesVersion === null || !config.supported_rules_versions.includes(rulesVersion)) {
    failures.push(
      `the corpus proof certifies rules_version "${rulesVersion}", which this configuration does not support`,
    );
  }

  // 2. The commitment the verifier carries.
  const carried = rulesVersion === null ? undefined : config.rules_corpus_roots?.[rulesVersion];
  if (typeof carried !== "string" || carried.length === 0 || carried === PENDING_CORPUS_PROOF) {
    failures.push(
      `this configuration carries no corpus commitment for "${rulesVersion}", so no corpus proof can be ` +
        "accepted for it (rules-domain/1 §13.3.1)",
    );
  } else if (carried !== subtreeRoot) {
    failures.push(
      `the corpus proof's subtree_root ${subtreeRoot} is not the commitment this configuration carries ` +
        `(${carried}): it is not the proof that certifies this rules domain`,
    );
  }

  // 3 and 4. The certified subject and the documents themselves.
  const certified = checkCertifiedCollection(baseCertificate, documents);
  failures.push(...certified.failures);
  const declared = certified.declared;
  const collection = { root: certified.collectionRoot };

  return {
    valid: failures.length === 0,
    failures,
    rules_version: rulesVersion,
    subtree_root: subtreeRoot,
    collection_root: collection.root,
    declared_cardinality: declared,
    verdict,
  };
}

/**
 * Links 3 and 4 of a corpus check, shared by every kind of certified collection:
 * the certificate commits to exactly one `subject.collection/1` whose leaves all
 * carry `leafProfile`, as many as the documents supplied, and each document reproduces its
 * leaf and the leaves fold to the signed root.
 */
function checkCertifiedCollection(
  baseCertificate: BaseCertificate | null,
  documents: RulesCorpusDocument[],
  leafProfile: string = TEXT_PROFILE,
): { failures: string[]; collectionRoot: string | null; declared: number | null } {
  const failures: string[] = [];
  // The certified subject.
  const subjects = baseCertificate?.payload?.anchor?.subjects ?? [];
  const collection = subjects.length === 1 ? subjects[0].collection : undefined;
  const leaves = collection?.leaves ?? [];
  const declared = collection ? Number(collection.declared_cardinality) : null;
  if (subjects.length !== 1 || subjects[0].profile !== COLLECTION_PROFILE || !collection) {
    failures.push(
      `the corpus certificate must commit to exactly one ${COLLECTION_PROFILE} subject ` +
        `(found ${subjects.length} subject(s): ${subjects.map((s) => s.profile).join(", ") || "none"})`,
    );
  } else {
    const foreign = leaves.filter((leaf) => leaf.profile !== leafProfile);
    if (foreign.length > 0) {
      failures.push(
        `every leaf of this collection is ${leafProfile}; ${foreign.length} is/are not ` +
          `(${[...new Set(foreign.map((l) => l.profile))].join(", ")})`,
      );
    }
    if (declared !== leaves.length || declared !== documents.length) {
      failures.push(
        `cardinality mismatch: the certificate declares ${collection.declared_cardinality} document(s), ` +
          `lists ${leaves.length} leaf/leaves, and ${documents.length} document(s) were supplied`,
      );
    }
  }

  // The documents themselves.
  // Each leaf is recomputed under the profile it declares, exactly as any verifier
  // recomputes a collection; link 3 has already required that profile.
  const nonceHex = baseCertificate?.payload?.anchor?.nonce_hex;
  const comparable = collection && declared === leaves.length && declared === documents.length;
  if (comparable && typeof nonceHex === "string" && nonceHex.length > 0) {
    const salt = new TextEncoder().encode(nonceHex);
    const recomputed = documents.map((doc, i) =>
      collectionLeafHash(salt, leaves[i].profile, canonicalBytesForSubject(leaves[i].profile, doc.bytes)),
    );
    const mismatched = recomputed.flatMap((hash, i) => (hash === leaves[i].commitment_digest_hex ? [] : [i]));
    for (const i of mismatched) {
      failures.push(
        `document ${i}${documents[i].path ? ` (${documents[i].path})` : ""} is not the content leaf ${i} certifies`,
      );
    }
    if (mismatched.length === 0 && collectionMerkleRoot(recomputed) !== collection.root) {
      failures.push("the documents do not fold to the collection root the certificate signs");
    }
  } else if (collection && (typeof nonceHex !== "string" || nonceHex.length === 0)) {
    failures.push("the corpus certificate carries no anchor nonce_hex, so its collection salt is unknown");
  }

  return { failures, collectionRoot: collection?.root ?? null, declared };
}

export interface CertifiedFilesResult {
  /** True only when every link of the chain holds. */
  valid: boolean;
  /** One line per broken link, in the order they were checked. Empty when valid. */
  failures: string[];
  /** The rules version the certifying proof was issued under. */
  rules_version: string | null;
  /** The certifying proof's anchored `subtree_root`. */
  subtree_root: string | null;
  /** The collection root the certificate signs over the files. */
  collection_root: string | null;
  declared_cardinality: number | null;
  /** The ordinary verdict on the certifying proof itself. */
  verdict: VerifierResult;
}

export interface CertifiedFile {
  /** The file's path in the repository. Reported, never committed: the leaf binds content and order. */
  path?: string;
  /** The file's exact bytes. */
  bytes: Uint8Array;
}

/**
 * Establish that a set of files is exactly what one publication certificate of a
 * repository certifies — each file byte for byte, in the order the certificate
 * lists them — without a live CERTCRYPT service and without trusting where the
 * files or the proof came from.
 *
 * The chain of `verifyRulesCorpus` without its commitment link, and with
 * `subject.binary/1` leaves: no verifier carries a commitment for a file, so the
 * anchor is the proof itself; and a file is certified as its exact bytes, with no
 * normalization, so the file that verifies is the file that was published.
 *
 * 1. The proof verifies as an ordinary proof: `INDEPENDENT_VALID` under
 *    `config`, for a `rules_version` the configuration supports.
 * 2. Its certificate commits to exactly one `subject.collection/1` whose leaves
 *    are all `subject.binary/1`, as many as the files supplied.
 * 3. Each file, salted with the certificate's anchor `nonce_hex`, reproduces its
 *    leaf, and the leaves fold to the signed collection root.
 *
 * It establishes that the files existed, exactly so, when the proof settled — not
 * that their content is correct.
 */
export function verifyCertifiedFiles(
  request: VerifierRequest,
  files: CertifiedFile[],
  config: SystemDomainConfig,
): CertifiedFilesResult {
  const failures: string[] = [];
  const verdict = verify(request, config);
  const { baseCertificate, independenceProof } = loadArtifacts(request) as {
    baseCertificate: BaseCertificate | null;
    independenceProof: IndependenceProof | null;
  };
  const rulesVersion = independenceProof?.rules_version ?? null;
  if (verdict.result_code !== "INDEPENDENT_VALID") {
    failures.push(
      `the certifying proof does not verify as independent: ${verdict.result_code}` +
        (verdict.failure_reason ? ` — ${verdict.failure_reason}` : ""),
    );
  }
  if (rulesVersion === null || !config.supported_rules_versions.includes(rulesVersion)) {
    failures.push(`the certifying proof was issued under rules_version "${rulesVersion}", which this configuration does not support`);
  }
  const certified = checkCertifiedCollection(baseCertificate, files, BINARY_PROFILE);
  failures.push(...certified.failures.map((f) => f.replace(/^document /, "file ")));
  return {
    valid: failures.length === 0,
    failures,
    rules_version: rulesVersion,
    subtree_root: independenceProof?.subtree_root ?? null,
    collection_root: certified.collectionRoot,
    declared_cardinality: certified.declared,
    verdict,
  };
}
