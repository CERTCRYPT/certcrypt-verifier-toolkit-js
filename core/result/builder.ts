import type {
  VerifierRequest,
  VerifierResult,
  CertcryptLineage,
  PqcVerificationResult,
  ResultCode,
  ResolvedTarget,
  CheckId,
  CheckResult,
  CheckFailureClassification,
  Diagnostic,
  DiagnosticLevel,
  SubjectScope,
  NodeAttestation,
} from "../types/index.js";
import { SUBJECT_COLLECTION } from "../crypto/canonical-subject.js";

const ISSUED_REQUIRED_CHECKS: CheckId[] = [
  "INPUT_TARGET_SUPPORTED",
  "INPUT_MODE_SUPPORTED",
  "INPUT_COMBINATION_VALID",
  "BASE_CERTIFICATE_PRESENT",
  "BASE_CERTIFICATE_STRUCTURE_VALID",
  "BASE_CERTIFICATE_AUTHENTIC",
];

const INDEPENDENT_REQUIRED_CHECKS: CheckId[] = [
  ...ISSUED_REQUIRED_CHECKS,
  "PROOF_PRESENT",
  "PROOF_VERSION_SUPPORTED",
  "PROOF_STRUCTURE_VALID",
  "RULES_DOMAIN_EXACT",
  "SYSTEM_DOMAIN_EXACT",
  "SYSTEM_ROOT_BINDING_VALID",
  "LEAF_BINDING_VALID",
  "SETTLEMENT_REF_VALID",
  "FINALITY_SUFFICIENT",
  "CAPACITY_BINDING_VALID",
  "CAPACITY_NOT_RECONSTRUCTED",
  "EFFECTIVE_UNITS_BINDING_VALID",
  "INCLUSION_PROOF_VALID",
  "AGGREGATED_INTERPRETATION_UNIQUE",
  "ISSUANCE_PARTICIPATION_VALID",
  // Mandatory under every rules domain (independence.proof/1 §10.13).
  "PROOF_SIGNATURE_VALID",
  "NON_REPLAY_VALID",
  "ANTI_SPLICING_VALID",
  "CLONE_OR_FORK_REJECTED",
];

/** Classification priority: higher index = higher priority for final result */
const CLASSIFICATION_PRIORITY: ResultCode[] = [
  "ISSUED_VALID",
  "INDEPENDENT_VALID",
  "INDEPENDENT_INVALID",
  "ISSUED_INVALID",
  "UNSUPPORTED",
  "INCOMPLETE",
  "REJECTED",
];

export class ResultBuilder {
  private readonly request: VerifierRequest;
  private resolvedTarget: ResolvedTarget | null = null;
  private checks: CheckResult[] = [];
  private missingArtifacts: string[] = [];
  private diagnosticsList: Diagnostic[] = [];
  private earlyExit = false;
  private _productionVerification = true;
  // Structural lineage — populated by settlement verification
  private _settlementProfileId: string | null = null;
  private _subtreeRoot: string | null = null;
  private _settlementRef: string | null = null;
  private _batchRoot: string | null = null;
  private _batchIndex: string | null = null;
  private _batchSize: string | null = null;
  // Foundation lineage — populated by foundation verification
  private _foundationProfileId: string | null = null;
  private _foundationStatementId: string | null = null;
  private _foundationPublicationRef: string | null = null;
  // Node attestation of the proof, recorded once PROOF_SIGNATURE_VALID passed.
  private _attestedNode: NodeAttestation | null = null;
  // Per-subject verdict scope — populated once the base certificate is parsed.
  private _subjectScope: SubjectScope[] | null = null;
  // ML-DSA-65 component outcome (normative, attributed to BASE_CERTIFICATE_AUTHENTIC),
  // surfaced separately — populated by verify-issued whenever the composite runs
  private _pqcResult: PqcVerificationResult = {
    performed: false,
    algorithm: "ML-DSA-65",
    passed: null,
    reason: "not_attempted",
  };
  // Original-material (complete verification) plane — opt-in. Stays
  // performed=false until verify-original-material actually runs the comparison
  // (i.e. material was delivered); then it reflects the real outcome so a caller
  // can tell "material verified" from "material not supplied / not performed".
  private _completeMaterialPerformed = false;
  private _completeMaterialPassed = false;

  constructor(request: VerifierRequest) {
    this.request = request;
  }

  setResolvedTarget(target: ResolvedTarget): void {
    this.resolvedTarget = target;
  }

  /** Record the proof's node attestation; reported only on INDEPENDENT_VALID. */
  setAttestedNode(attestation: NodeAttestation | null): void {
    this._attestedNode = attestation
      ? { node_id: attestation.node_id, recognized_at: attestation.recognized_at }
      : null;
  }

  setLineage(lineage: {
    settlement_profile_id?: string;
    subtree_root?: string;
    settlement_ref?: string;
    batch_root?: string;
    batch_index?: string;
    batch_size?: string;
  }): void {
    if (lineage.settlement_profile_id) this._settlementProfileId = lineage.settlement_profile_id;
    if (lineage.subtree_root) this._subtreeRoot = lineage.subtree_root;
    if (lineage.settlement_ref) this._settlementRef = lineage.settlement_ref;
    if (lineage.batch_root) this._batchRoot = lineage.batch_root;
    if (lineage.batch_index !== undefined) this._batchIndex = lineage.batch_index;
    if (lineage.batch_size) this._batchSize = lineage.batch_size;
  }

  setFoundationLineage(lineage: {
    foundation_profile_id?: string;
    foundation_statement_id?: string;
    foundation_publication_ref?: string;
  }): void {
    if (lineage.foundation_profile_id) this._foundationProfileId = lineage.foundation_profile_id;
    if (lineage.foundation_statement_id) this._foundationStatementId = lineage.foundation_statement_id;
    if (lineage.foundation_publication_ref) this._foundationPublicationRef = lineage.foundation_publication_ref;
  }

  setPqcResult(result: PqcVerificationResult): void {
    this._pqcResult = result;
  }

  /**
   * Record the per-subject verdict scope from the base certificate's anchor
   * subjects, in order. Only `subject.collection/1` declares its elements
   * (`opaque: false`); every other profile is a single opaque subject whose
   * internal contents the proof does NOT cover. Called once the base certificate
   * is parsed. Makes an `INDEPENDENT_VALID` over an opaque subject (e.g. a ZIP as
   * `subject.binary/1`) distinguishable, in the result, from one over a declared
   * collection — closing the "container covers its children" over-read.
   */
  setSubjectScope(subjectProfiles: string[]): void {
    this._subjectScope = subjectProfiles.map((profile) => ({
      profile,
      opaque: profile !== SUBJECT_COLLECTION,
    }));
  }

  /** Record that the complete-verification-against-material plane ran, and
   *  its outcome. Called by verify-original-material when material is delivered. */
  setCompleteMaterialResult(performed: boolean, passed: boolean): void {
    this._completeMaterialPerformed = performed;
    this._completeMaterialPassed = passed;
  }

  addCheck(result: CheckResult): void {
    this.checks.push(result);
  }

  pass(checkId: CheckId, message?: string): void {
    this.checks.push({ check_id: checkId, passed: true, message });
  }

  fail<C extends CheckId>(
    checkId: C,
    classification: CheckFailureClassification<C>,
    message?: string
  ): void {
    this.checks.push({
      check_id: checkId,
      passed: false,
      failure_classification: classification,
      message,
    });
    this.addDiagnostic("error", message ?? `Check ${checkId} failed`, checkId);
  }

  addMissingArtifact(artifactName: string): void {
    if (!this.missingArtifacts.includes(artifactName)) {
      this.missingArtifacts.push(artifactName);
    }
  }

  addDiagnostic(
    level: DiagnosticLevel,
    message: string,
    checkId?: CheckId
  ): void {
    this.diagnosticsList.push({
      level,
      message,
      check_id: checkId ?? null,
    });
  }

  hasFailure(): boolean {
    return this.checks.some((c) => !c.passed);
  }

  /** True when the named check has run and failed. */
  hasFailed(checkId: CheckId): boolean {
    return this.checks.some((c) => c.check_id === checkId && !c.passed);
  }

  /**
   * Returns the current check count. Used to create a checkpoint so that
   * downstream logic can detect failures added after a certain point
   * without being affected by earlier failures (e.g., Issued UNSUPPORTED
   * should not prevent Independent checks from running).
   */
  checkpoint(): number {
    return this.checks.length;
  }

  /**
   * Returns true if any check added after the given checkpoint failed.
   */
  hasFailureSince(checkpoint: number): boolean {
    return this.checks.slice(checkpoint).some((c) => !c.passed);
  }

  markEarlyExit(): void {
    this.earlyExit = true;
  }

  /**
   * Mark that verification ran under a configuration other than the published
   * production profile. Surfaced as `production_verification: false` so a
   * *_VALID result cannot be mistaken for a verdict about the production domain.
   */
  markNonProductionVerification(): void {
    this._productionVerification = false;
  }

  build(): VerifierResult {
    // Before the target is resolved (an input that fails first) the result
    // reports the target the request named: a request for `independent` that
    // is refused at the input is not an Issued verification. `auto` names no
    // route yet, and reports Issued, the route that claims less.
    const target =
      this.resolvedTarget ??
      (this.request.verification_target_requested === "independent" ? "Independent" : "Issued");
    const failedChecks = this.checks.filter((c) => !c.passed);
    const failedCheckIds = failedChecks.map((c) => c.check_id);

    // Determine result code
    let resultCode: ResultCode;

    if (failedChecks.length === 0 && !this.earlyExit) {
      // Check that all required checks for this target were actually executed
      const requiredChecks: CheckId[] = [
        ...(target === "Independent"
          ? this.requiredIndependentChecks()
          : ISSUED_REQUIRED_CHECKS),
        // A package is read only after its structure and its declarations were
        // checked (verifier-toolkit/1 §11.1, §11.2 steps 1–2).
        ...(this.request.input_mode === "package"
          ? (["PACKAGE_STRUCTURE_VALID", "PACKAGE_CONTEXT_COHERENT"] as CheckId[])
          : []),
      ];
      const executedCheckIds = new Set(this.checks.map((c) => c.check_id));
      const missingRequired = requiredChecks.filter(
        (id) => !executedCheckIds.has(id)
      );

      if (missingRequired.length > 0) {
        // Fail-closed: required checks not executed
        resultCode = "INCOMPLETE";
        for (const missing of missingRequired) {
          failedCheckIds.push(missing);
          this.diagnosticsList.push({
            level: "error",
            message: `Required check ${missing} was not executed`,
            check_id: missing,
          });
        }
      } else {
        resultCode =
          target === "Independent" ? "INDEPENDENT_VALID" : "ISSUED_VALID";
      }
    } else {
      // Find highest-priority failure classification
      resultCode = this.deriveFailureCode(failedChecks, target);
    }

    // Derive per-axis booleans
    const passedIds = new Set(
      this.checks.filter((c) => c.passed).map((c) => c.check_id)
    );
    const failedIds = new Set(failedCheckIds);

    const domainValid =
      passedIds.has("SYSTEM_DOMAIN_EXACT") &&
      passedIds.has("SYSTEM_ROOT_BINDING_VALID") &&
      !failedIds.has("CLONE_OR_FORK_REJECTED");

    const rulesDomainValid = passedIds.has("RULES_DOMAIN_EXACT");

    const issuedValid =
      passedIds.has("BASE_CERTIFICATE_STRUCTURE_VALID") &&
      passedIds.has("BASE_CERTIFICATE_AUTHENTIC");

    /**
     * The Independent AXIS, derived from its own checks — not copied from
     * `result_code`.
     *
     * These booleans are per-axis by design (see the comment above), and this one
     * is computed from `passedIds` like every other. It does not follow
     * `result_code`: a check outside the axis must not collapse it. Supplying
     * original material for some subjects but not all fails
     * ORIGINAL_MATERIAL_COMPARISON_VALID and makes `result_code` INCOMPLETE, yet
     * ORIGINAL_MATERIAL_COMPARISON_VALID is NOT in INDEPENDENT_REQUIRED_CHECKS
     * (nor in the operational variant): the axis does not depend on material, so
     * adding information never appears to invalidate independence.
     *
     * `result_code` keeps INCOMPLETE in that case, because a
     * comparison WAS requested and could not be finished (`verifier-toolkit/1`
     * §8.5.1 fixes that outcome so toolkits converge). The two answer different
     * questions — "does the independence plane hold?" and "did everything asked for
     * complete?" — and only the second one is affected by partial material.
     *
     * Requires the target to BE Independent: on an Issued-only run the axis was
     * never evaluated, and reporting true would claim a plane nobody checked.
     */
    const independentValid =
      target === "Independent" &&
      this.requiredIndependentChecks().every(
        (id: CheckId) => passedIds.has(id) && !failedIds.has(id)
      );

    const proofComplete =
      passedIds.has("PROOF_PRESENT") &&
      passedIds.has("PROOF_STRUCTURE_VALID") &&
      this.missingArtifacts.length === 0;

    // Extract system info from checks
    const systemId = this.extractSystemId();
    const systemRootIdentifier = this.extractSystemRootIdentifier();
    const rulesVersion = this.extractRulesVersion();

    // Failure reason
    const failureReason =
      failedChecks.length > 0
        ? failedChecks.map((c) => c.message ?? c.check_id).join("; ")
        : null;

    // Derive certcrypt_lineage from existing checks and fields only
    const certcryptLineage = this.deriveCertcryptLineage(
      independentValid,
      domainValid,
      passedIds,
      systemId,
      rulesVersion,
      systemRootIdentifier
    );

    return {
      result_code: resultCode,
      verification_target_requested: this.request.verification_target_requested,
      verification_target_resolved: target,
      verification_target: target,
      input_mode: this.request.input_mode,
      production_verification: this._productionVerification,
      domain_valid: domainValid,
      rules_domain_valid: rulesDomainValid,
      issued_valid: issuedValid,
      independent_valid: independentValid,
      proof_complete: proofComplete,
      complete_verification_against_original_material_performed: this._completeMaterialPerformed,
      complete_verification_against_original_material_passed: this._completeMaterialPassed,
      failure_reason: failureReason,
      failed_check_ids: [...new Set(failedCheckIds)],
      required_artifacts_missing: [...this.missingArtifacts],
      applicable_rules_version: rulesVersion,
      system_id: systemId,
      system_root_identifier: systemRootIdentifier,
      settlement_profile_id: this._settlementProfileId,
      subtree_root: this._subtreeRoot,
      settlement_ref: this._settlementRef,
      batch_root: this._batchRoot,
      batch_index: this._batchIndex,
      batch_size: this._batchSize,
      foundation_profile_id: this._foundationProfileId,
      foundation_statement_id: this._foundationStatementId,
      foundation_publication_ref: this._foundationPublicationRef,
      subject_scope: this._subjectScope,
      attested_node: resultCode === "INDEPENDENT_VALID" ? this._attestedNode : null,
      diagnostics: this.diagnosticsList,
      certcrypt_lineage: certcryptLineage,
      additional_verifications: {
        pqc_base_certificate_authentic: this._pqcResult,
      },
    };
  }

  private requiredIndependentChecks(): CheckId[] {
    return INDEPENDENT_REQUIRED_CHECKS;
  }

  /**
   * Derive certcrypt_lineage block from existing checks and fields.
   * No new verification logic — purely a projection of already-validated state.
   */
  private deriveCertcryptLineage(
    independentValid: boolean,
    domainValid: boolean,
    passedIds: Set<CheckId>,
    systemId: string | null,
    rulesVersion: string | null,
    systemRootIdentifier: string | null
  ): CertcryptLineage {
    const certcryptDomainBound = domainValid;

    const independenceUnderCertcryptRules = independentValid;

    const settlementBound =
      passedIds.has("SETTLEMENT_REF_VALID") &&
      passedIds.has("FINALITY_SUFFICIENT") &&
      passedIds.has("INCLUSION_PROOF_VALID") &&
      passedIds.has("AGGREGATED_INTERPRETATION_UNIQUE");

    const capacityConsumptionBound =
      passedIds.has("CAPACITY_BINDING_VALID") &&
      passedIds.has("CAPACITY_NOT_RECONSTRUCTED");

    const historyBoundUnderCertcrypt =
      certcryptDomainBound &&
      settlementBound &&
      capacityConsumptionBound &&
      independenceUnderCertcryptRules;

    return {
      certcrypt_domain_bound: certcryptDomainBound,
      independence_under_certcrypt_rules: independenceUnderCertcryptRules,
      settlement_bound: settlementBound,
      capacity_consumption_bound: capacityConsumptionBound,
      history_bound_under_certcrypt: historyBoundUnderCertcrypt,
      system_id: systemId,
      rules_version: rulesVersion,
      system_root_fingerprint: systemRootIdentifier,
      settlement_profile_id: this._settlementProfileId,
      subtree_root: this._subtreeRoot,
      settlement_ref: this._settlementRef,
      foundation_profile_id: this._foundationProfileId,
      foundation_statement_id: this._foundationStatementId,
    };
  }

  private deriveFailureCode(
    failedChecks: CheckResult[],
    target: ResolvedTarget
  ): ResultCode {
    // Priority (verifier-toolkit/1 §9.5): REJECTED > INCOMPLETE > UNSUPPORTED >
    // ISSUED_INVALID > INDEPENDENT_INVALID
    let highestPriority = -1;
    let highestCode: ResultCode =
      target === "Independent" ? "INDEPENDENT_INVALID" : "ISSUED_INVALID";

    for (const check of failedChecks) {
      let classification: ResultCode =
        check.failure_classification ?? highestCode;
      // An Issued verification never reports a code of the Independent route.
      if (target === "Issued" && classification === "INDEPENDENT_INVALID") {
        classification = "ISSUED_INVALID";
      }
      const priority = CLASSIFICATION_PRIORITY.indexOf(classification);
      if (priority > highestPriority) {
        highestPriority = priority;
        highestCode = classification;
      }
    }

    return highestCode;
  }

  private extractSystemId(): string | null {
    for (const d of this.diagnosticsList) {
      if (d.check_id === "SYSTEM_DOMAIN_EXACT" && d.message.includes("system_id=")) {
        return d.message.split("system_id=")[1]?.split(";")[0] ?? null;
      }
    }
    return null;
  }

  private extractSystemRootIdentifier(): string | null {
    for (const d of this.diagnosticsList) {
      if (d.check_id === "SYSTEM_ROOT_BINDING_VALID" && d.message.includes("root=")) {
        return d.message.split("root=")[1]?.split(";")[0] ?? null;
      }
    }
    return null;
  }

  private extractRulesVersion(): string | null {
    for (const d of this.diagnosticsList) {
      if (d.check_id === "RULES_DOMAIN_EXACT" && d.message.includes("rules_version=")) {
        return d.message.split("rules_version=")[1]?.split(";")[0] ?? null;
      }
    }
    return null;
  }
}
