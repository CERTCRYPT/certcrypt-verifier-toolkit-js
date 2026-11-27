import type {
  BaseCertificate,
  VerificationPackage,
  SubjectMaterialMap,
} from "./artifacts.js";
import type { IndependenceProof } from "./proof.js";
import type {
  SettlementMaterial,
  CommitmentInclusionProof,
} from "./settlement-material.js";
import type { CapacityEvidence } from "./capacity-evidence.js";
import type { SystemFoundation } from "./foundation.js";

export type VerificationTargetRequested = "auto" | "issued" | "independent";
export type InputMode = "package" | "artifact_set";

export interface VerifierRequest {
  verification_target_requested: VerificationTargetRequested;
  input_mode: InputMode;

  // ── In-memory artifacts ────────────────────────────────────────────────────
  // Every `*_path` below has an in-memory counterpart here. Supply either form:
  // the in-memory value WINS when both are present.
  //
  // Why both exist: the CLI reads files, a service receives bytes over the wire.
  // Forcing the second through a temp file would put disk I/O on a request's hot
  // path — and force a caller to serialize something it already holds parsed.
  // These are two legitimate ways into the same verification core, not a
  // migration: neither form is deprecated.
  //
  // Note the toolkit never *fetches* anything. Passing an object is not a
  // network call: verification stays offline either way.

  /** The `verification_package`, already parsed. Wins over `..._path`. */
  verification_package?: VerificationPackage;
  /** The signed base certificate, already parsed. Wins over `..._path`. */
  base_certificate?: BaseCertificate;
  /** The `independence_proof`, already parsed. Wins over `..._path`. */
  independence_proof?: IndependenceProof;
  /** Settlement material, already parsed. Wins over `..._path`. */
  settlement_material?: SettlementMaterial;
  /** Capacity evidence, already parsed. Wins over `..._path`. */
  capacity_evidence?: CapacityEvidence;
  /** Per-commitment inclusion proof, already parsed. Wins over `..._path`. */
  commitment_inclusion_proof?: CommitmentInclusionProof;
  /** System foundation, already parsed. Wins over `..._path`. */
  system_foundation?: SystemFoundation;
  /**
   * Subject-material map: zero-based subject index → that subject's
   * material — raw bytes, `{ leaves[] }` for a collection subject,
   * `{ prehashed: true, subject_local_digest_hex }` for a streamed
   * `subject.binary/1`, or `{ record, materials: Map<id, bytes|prehashed> }` for an AI-decision
   * subject. Wins over `original_material_path`.
   *
   * The single-subject case is the common one, so a bare `Uint8Array` is
   * accepted as shorthand for subject 0.
   */
  original_material?: SubjectMaterialMap | Uint8Array;

  // ── File paths ─────────────────────────────────────────────────────────────
  verification_package_path?: string;
  base_certificate_path?: string;
  independence_proof_path?: string;
  /** Accepted by the request schema; this toolkit reads none of these paths. */
  supporting_artifact_paths?: string[];
  original_material_path?: string;
  /** Accepted by the request schema; this toolkit reads none of these paths. */
  system_domain_artifact_paths?: string[];
  /**
   * Accepted by the request schema; this toolkit reads none of these paths. The
   * rules a verification applies come from the profile, never from the request.
   */
  rules_artifact_paths?: string[];
  settlement_material_path?: string;
  /** Zero-data capacity evidence. Required for `Independent`. */
  capacity_evidence_path?: string;
  /**
   * Per-commitment inclusion proof (`commitment → subtree_root`) for the
   * certificate under verification (leaf=subtree, independence.proof/1).
   * Required for `Independent`.
   */
  commitment_inclusion_proof_path?: string;
  system_foundation_path?: string;
}
