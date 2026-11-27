import type { ComponentSignature } from "../crypto/composite.js";
import type { IndependenceProof } from "./proof.js";
import type {
  SettlementMaterial,
  CommitmentInclusionProof,
} from "./settlement-material.js";
import type { SystemFoundation } from "./foundation.js";
import type { CapacityEvidence } from "./capacity-evidence.js";

/**
 * A `subject.collection/1` material entry: the ordered list of leaf materials
 * that reconstruct its root, optionally with a copy of the collection
 * descriptor (verifier-toolkit/1).
 */
export interface CollectionMaterial {
  /**
   * Optional delivered copy of the collection descriptor. The AUTHORITATIVE descriptor
   * is the one signed in `subjects[i].collection`; when this is present it MUST match
   * it canonically, so a stale copy fails loudly instead of overriding the signed one.
   */
  collection?: unknown;
  /** Ordered leaf materials, exactly `declared_cardinality` of them. */
  leaves: Uint8Array[];
}

/**
 * A subject whose canonical digest was computed OUTSIDE this library, incrementally, and
 * whose bytes are therefore not retained.
 *
 * This exists for one reason: a browser cannot hold a multi-gigabyte file in a single
 * `ArrayBuffer`, so the caller streams it, hashes it chunk by chunk, and hands over the
 * digest instead of the bytes. The verdict is identical either way — the commitment is
 * computed from `subject_local_digest_hex`, and that hex string is all this carries.
 *
 * **Valid ONLY for `subject.binary/1`.** That profile alone defines canonical_bytes as the
 * exact input bytes, which makes a chunk-by-chunk digest equal to the whole-buffer digest.
 * Every other profile transforms the material first — `subject.text/1` normalizes line
 * endings, `subject.email/1` unfolds headers, the JSON-object profiles re-serialize the
 * PARSED value under JCS — and none of those transformations is chunk-local. A prehashed
 * entry on any other profile is REJECTED rather than trusted: accepting it would let a
 * caller substitute a digest of the raw bytes for a digest of the canonical bytes, which is
 * a different value, and the mismatch would look like a verification failure of the
 * material rather than a misuse of this type.
 */
export interface PrehashedMaterial {
  /**
   * Discriminant. Present so the shape cannot be produced by accident: a caller reaching
   * for this must name it, and `instanceof Uint8Array` checks elsewhere keep working.
   */
  readonly prehashed: true;
  /** Lowercase hex SHA3-256 of the subject's canonical bytes — for binary/1, of the file. */
  readonly subject_local_digest_hex: string;
  /**
   * Byte length of the material that was hashed. Not used in the commitment; carried so a
   * caller can report what it read, and so a zero-length stream is distinguishable from an
   * unread one.
   */
  readonly byte_length?: number;
}

/**
 * A `subject.ai-decision/1` material entry that also carries any disclosed input
 * or output parts, keyed by the id that is unique within the matched record.
 *
 * The record is compared against the certificate before `materials` is inspected.
 * Each delivered part is canonicalized under the profile declared by the matched
 * record. A binary part may instead carry a verifier-local streamed digest.
 */
export interface AiDecisionMaterial {
  record: Uint8Array;
  materials: Map<string, Uint8Array | PrehashedMaterial>;
}

/**
 * Verifier-local subject-material map: zero-based subject index → that subject's
 * material. A collection subject maps to `CollectionMaterial`; an AI-decision subject
 * maps to its record bytes or to an `AiDecisionMaterial`; any other profile maps to its
 * raw bytes, or to a `PrehashedMaterial` when the caller streamed it.
 * Verifier-local apparatus — never published.
 */
export type SubjectMaterialMap = Map<
  number,
  Uint8Array | CollectionMaterial | PrehashedMaterial | AiDecisionMaterial
>;

/**
 * CCSP/1-conformant base certificate model.
 *
 * Per CCSP/1: payload is the sole carrier of normative semantics.
 * Normative cross-artifact fields (system_id, rules_version) live inside the
 * signed payload. Under the leaf=subtree hybrid binding the leaf-bound value
 * is NOT carried in the cert (the link is SHA3(cert)==certificate_commitment_
 * digest + commitment_id∈subtree_root, verified in the Independent path).
 * PQC dual-sign uses a second entry in signatures[], not top-level fields.
 */
export interface BaseCertificate {
  schema?: string;
  metadata?: Record<string, unknown>;
  payload: CertificatePayload;
  signatures: CertificateSignature[];
  payload_canon_digest_hex?: string;
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * CCSP/1 payload — the signed content.
 * Per CCSP/1 and CCCP/1.
 */
export interface CertificatePayload {
  anchor: CertificateAnchor;
  /** CCCP/1: SHA3-256(ASCII(nonce_hex) || ASCII(SHA3-256(JCS(anchor)))) */
  anchor_commitment_digest_hex?: string;
  /** Normative system identity — MUST be inside signed payload */
  system_id?: string;
  /** Normative rules version — MUST be inside signed payload */
  rules_version?: string;
  [key: string]: unknown;
}

/**
 * CCSP/1 anchor — issuance anchor object.
 * Per CCSP/1.
 */
export interface CertificateAnchor {
  /** RFC 3339 UTC timestamp */
  issued_at: string;
  /** Lowercase hex, 64 chars, per-certificate CSPRNG nonce */
  nonce_hex: string;
  /** Array of subject commitment objects */
  subjects: SubjectCommitment[];
  /** Optional issuance-time root participation reference */
  root_id?: string;
  [key: string]: unknown;
}

/**
 * CCSP/1 subject commitment entry.
 * Per CCSP/1.
 */
export interface SubjectCommitment {
  profile: string;
  commitment_digest_hex: string;
  /**
   * `subject.collection/1` only: the signed collection descriptor. CCSP/1 §7.3.2 permits
   * additional members whose meaning a referenced normative spec defines; this is that
   * case. It rides inside the subject so each leaf's profile enters the signature —
   * the profile decides how a leaf canonicalizes, so an unsigned one would be forgeable.
   */
  collection?: CollectionDescriptor;
}

/** The signed `subject.collection/1` descriptor — four members (§7). */
export interface CollectionDescriptor {
  commitment_scheme: string;
  root: string;
  declared_cardinality: string;
  /** Ordered; the position IS the leaf index. Each entry declares its own profile (§7.4). */
  leaves: { profile: string; commitment_digest_hex: string }[];
}

/**
 * CCSP/1 signature entry — composite (CERTCRYPT Composite Signature Profile), canonical profile P-256 + ML-DSA.
 *
 * The issuer signature is a single composite entry (`alg` =
 * "certcrypt-composite-p256-mldsa65-v1") carrying its ordered component
 * signatures (classical first, ML-DSA second) in `signatures[]`. All sign the
 * same domain-separated M' (see crypto/composite.ts); verification is AND. The
 * composite is the one normative emission signature — there is no standalone
 * classical or ML-DSA-65 issuer entry.
 */
export interface CertificateSignature {
  role: string;
  sig_target: string;
  /** Composite profile id, e.g. "certcrypt-composite-p256-mldsa65-v1". */
  alg: string;
  /** Composite mode (always "AND"). */
  mode: string;
  /** Ordered component signatures (classical first, ML-DSA second). */
  signatures: ComponentSignature[];
  signer: {
    id: string;
    /** ECDSA P-256 component public key (SEC1, base64). */
    pub_p256_b64: string;
    /** ML-DSA-65 component public key (base64). */
    pub_mldsa_b64: string;
  };
  kid?: string;
}

/**
 * A `verification_package` (verification-package/1 §22.1): one JSON object with
 * a closed member set. Original material is never a member (§10).
 */
export interface VerificationPackage {
  base_certificate: BaseCertificate;
  verification_context: { rules_version: string; system_id: string };
  independence_proof?: IndependenceProof;
  capacity_evidence?: CapacityEvidence;
  commitment_inclusion_proof?: CommitmentInclusionProof;
  settlement_material?: SettlementMaterial;
  settlement_reference?: string;
}

export interface LoadedArtifacts {
  baseCertificate: BaseCertificate | null;
  independenceProof: IndependenceProof | null;
  settlementMaterial: SettlementMaterial | null;
  /**
   * Zero-data capacity evidence for the certificate under verification. The
   * verifier runs the capacity proof for itself (`verifyCapacityEvidence`) and
   * binds it to the consumed commitment by requiring its digest to equal that
   * commitment's `commitment_id` (`capacity.evidence/1`).
   */
  capacityEvidence: CapacityEvidence | null;
  /**
   * Per-commitment inclusion proof (`commitment → subtree_root`) for the
   * certificate under verification (leaf=subtree). Consumed by the hybrid
   * emission binding (LEAF_BINDING_VALID step 2). Null when not supplied, which
   * leaves an Independent verification INCOMPLETE.
   */
  commitmentInclusionProof: CommitmentInclusionProof | null;
  verificationPackage: VerificationPackage | null;
  originalMaterialPath: string | null;
  /**
   * Verifier-local subject-material map (verifier-toolkit/1): zero-based
   * subject index → that subject's material. For a `subject.collection/1`
   * subject the value is `{ leaves[], collection? }` (the ordered leaf materials,
   * optionally with a copy of the signed descriptor); for any other profile it is
   * the subject's raw bytes, a `PrehashedMaterial` or an `AiDecisionMaterial`. Loaded by the input layer from `originalMaterialPath`
   * (or supplied directly). Null when no original material is provided — the
   * complete-verification plane is then simply not performed.
   */
  originalMaterial: SubjectMaterialMap | null;
  systemFoundation: SystemFoundation | null;
}
