import type { VerificationTargetRequested, InputMode } from "./request.js";
import type { NodeAttestation } from "./proof.js";

export type ResultCode =
  | "ISSUED_VALID"
  | "ISSUED_INVALID"
  | "INDEPENDENT_VALID"
  | "INDEPENDENT_INVALID"
  | "INCOMPLETE"
  | "UNSUPPORTED"
  | "REJECTED";

export type ResolvedTarget = "Issued" | "Independent";
export type DiagnosticLevel = "info" | "warning" | "error";

export interface Diagnostic {
  level: DiagnosticLevel;
  message: string;
  check_id?: string | null;
}

export interface VerifierResult {
  result_code: ResultCode;
  verification_target_requested: VerificationTargetRequested;
  verification_target_resolved: ResolvedTarget;
  verification_target: ResolvedTarget;
  input_mode: InputMode;
  /**
   * True only when the ENTIRE configuration equals the published production
   * profile: the same system id, root fingerprint,
   * XRPL chain id, MPT issuance, settlement account, token symbol, action name,
   * signature profile, foundation statement id and payload digest, admitted
   * subject profiles, settlement profile, supported rules versions and
   * per-version corpus roots.
   * False for any other configuration (a test domain, a synthetic root). Every
   * signature is verified in both cases; a *_VALID result with this false says
   * the artifacts verify under that other configuration, not under the
   * production domain.
   *
   * It surfaces the regime that produced a result as a boolean a consumer
   * cannot programmatically ignore, rather than only as a text diagnostic.
   */
  production_verification: boolean;
  domain_valid: boolean;
  rules_domain_valid: boolean;
  issued_valid: boolean;
  independent_valid: boolean;
  proof_complete: boolean;
  complete_verification_against_original_material_performed: boolean;
  complete_verification_against_original_material_passed: boolean;
  failure_reason: string | null;
  failed_check_ids: string[];
  required_artifacts_missing: string[];
  applicable_rules_version: string | null;
  system_id: string | null;
  system_root_identifier: string | null;
  // Structural lineage fields — make the CERTCRYPT binding visible in the result
  settlement_profile_id: string | null;
  subtree_root: string | null;
  settlement_ref: string | null;
  batch_root: string | null;
  batch_index: string | null;
  batch_size: string | null;
  // Foundation lineage — visible when system_foundation is validated
  foundation_profile_id: string | null;
  foundation_statement_id: string | null;
  foundation_publication_ref: string | null;
  /**
   * Per-subject scope of the verdict, in anchor order. Surfaces WHAT the verdict
   * covers so a consumer cannot silently over-read it: a subject submitted as a
   * single opaque input (`opaque: true` — e.g. `subject.binary/1`, an archive or
   * blob) is bound as that one input, and the verdict asserts nothing about any
   * elements contained within it. Coverage of multiple elements individually
   * exists only where the issuer declared them (e.g. `subject.collection/1`,
   * `opaque: false`). Proving a container is not proving its contents; this field
   * makes an `INDEPENDENT_VALID` over an opaque subject distinguishable from one
   * over a declared collection. Null until the base certificate is parsed.
   */
  subject_scope: SubjectScope[] | null;
  /**
   * The node the proof attests (independence.proof/1 §10.15): the recognized
   * node the submission entered through and the instant its recognition was
   * checked, authenticated by the proof signature. Set only on
   * `INDEPENDENT_VALID`; null otherwise and when the proof carries no
   * attestation. It names a transport, not the issuer, and asserts nothing
   * about the certified content.
   */
  attested_node: NodeAttestation | null;
  diagnostics: Diagnostic[];
  certcrypt_lineage: CertcryptLineage;
  additional_verifications: AdditionalVerifications;
}

/**
 * The scope of the verdict for one subject, in anchor order. `profile` is the
 * declared subject profile (`anchor.subjects[i].profile`, e.g. `subject.binary/1`,
 * `subject.collection/1`). `opaque` is true when the subject is a single opaque
 * input whose internal elements the proof does NOT cover — the verifier never
 * looks inside it. A collection (`opaque: false`) declares its elements, so the
 * verdict covers them at the declared resolution.
 */
export interface SubjectScope {
  profile: string;
  opaque: boolean;
}

/**
 * Outcomes surfaced separately from the check list — currently the ML-DSA-65
 * component of the base certificate's composite signature. The component itself
 * is normative: it is verified inside BASE_CERTIFICATE_AUTHENTIC, and a
 * certificate whose ML-DSA-65 half is absent, malformed or fails to verify does
 * not pass that check (core/crypto/composite.ts `verifyComposite`, AND semantics;
 * core/issued/verify-issued.ts). Nothing here alters result_code independently of
 * the check it belongs to.
 */
export interface AdditionalVerifications {
  pqc_base_certificate_authentic: PqcVerificationResult;
}

/**
 * Outcome of the ML-DSA-65 component of the base certificate's composite
 * signature, reported on its own. The component is mandatory (the post-quantum
 * floor): its failure fails BASE_CERTIFICATE_AUTHENTIC. This field reports that
 * outcome separately; it does not make the component optional, and it is not
 * where the verdict is decided.
 */
export interface PqcVerificationResult {
  /** True only if PQC verification was actually attempted. */
  performed: boolean;
  /** The PQC algorithm attempted. */
  algorithm: "ML-DSA-65";
  /** True if attempted and passed. False if attempted and failed. Null if not attempted. */
  passed: boolean | null;
  /** Reason for skip or failure. Null if performed and passed. */
  reason: string | null;
}

/**
 * Secondary visibility block — projects already-validated CERTCRYPT binding
 * into a compact, consumer-readable form.
 *
 * This block does not introduce new verification logic.
 * It does not add semantic overclaiming.
 * Every boolean and identifier is derived from existing checks and fields.
 */
export interface CertcryptLineage {
  /** True only if the verifier established exact CERTCRYPT system-domain binding. */
  certcrypt_domain_bound: boolean;
  /**
   * True only if the independence AXIS holds — every check
   * INDEPENDENT_REQUIRED_CHECKS lists, on a run that resolved to the Independent
   * target. A projection of `independent_valid`, so the two cannot disagree.
   *
   * Deliberately NOT `result_code === "INDEPENDENT_VALID"`: a failure OUTSIDE the
   * axis (notably a partial original-material comparison, which §8.5.1 classifies
   * INCOMPLETE) leaves independence intact and must not clear this.
   */
  independence_under_certcrypt_rules: boolean;
  /** True only if the verifier established the exact settlement-backed path. */
  settlement_bound: boolean;
  /** True only if the verifier established valid capacity-consumption binding. */
  capacity_consumption_bound: boolean;
  /**
   * True only if the result is structurally tied to the CERTCRYPT domain
   * through settlement-backed independent verification.
   *
   * Conservative: false whenever any of the four bindings above is false — an
   * unsupported profile, a domain mismatch, a missing settlement or a broken
   * capacity binding all clear it. What does NOT clear it is an unfinished
   * original-material comparison: that is completeness, not lineage.
   */
  history_bound_under_certcrypt: boolean;

  system_id: string | null;
  rules_version: string | null;
  system_root_fingerprint: string | null;

  settlement_profile_id: string | null;
  subtree_root: string | null;
  settlement_ref: string | null;

  foundation_profile_id: string | null;
  foundation_statement_id: string | null;
}
