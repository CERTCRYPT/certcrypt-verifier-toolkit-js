import type {
  VerifierRequest,
  VerifierResult,
  SystemDomainConfig,
} from "./types/index.js";
import { ResultBuilder } from "./result/builder.js";
import { validateInput } from "./input/validate.js";
import { resolveTarget } from "./input/resolve-target.js";
import { verifyIssued } from "./issued/verify-issued.js";
import { verifyPackageContext } from "./package/verify-package.js";
import { verifyIndependent } from "./independent/verify-independent.js";
import { verifyFoundation, foundationPayloadDigest } from "./foundation/verify-foundation.js";
import { getCertcryptConfig } from "./config/default.js";
import { initMlDsa65 } from "./crypto/ml-dsa.js";

// Start loading the ML-DSA-65 backend (async, non-blocking). verify() itself is
// synchronous, so a caller that verifies right away awaits initMlDsa65() first.
initMlDsa65().catch(() => {/* optional dep — ignore */});

/**
 * Main verification entry point.
 *
 * @param request  The verification request
 * @param configOverride  Optional config override (test-only). When omitted,
 *                        uses getCertcryptConfig(), the published production profile.
 *
 * Per verifier-toolkit/1:
 * 1. Validate input
 * 2. Resolve target
 * 3. Validate foundation (if present) — derive system_root_fingerprint
 * 4. Validate package (if package mode)
 * 5. Run Issued checks (always — per section 11.2 step 3)
 * 6. Run Independent checks (if target is Independent)
 * 7. Build and return result
 */
export function verify(
  request: VerifierRequest,
  configOverride?: SystemDomainConfig
): VerifierResult {
  const config = configOverride ?? getCertcryptConfig();
  const builder = new ResultBuilder(request);

  // Hardening: a *_VALID outcome may be labeled
  // production-grade ONLY when the ENTIRE config matches the published production
  // profile — not just the root fingerprint. Otherwise a caller
  // could inject the published root into an otherwise-test config (synthetic
  // chain_id, a test rules domain) and have a test verdict pass as production
  // (e.g. the CLI's `--test-root-fingerprint` set to the published root). Every
  // field that defines the operative production environment must match.
  const published = getCertcryptConfig();
  const isProductionProfile =
    config.system_root_fingerprint === published.system_root_fingerprint &&
    config.system_id === published.system_id &&
    config.xrpl_chain_id === published.xrpl_chain_id &&
    config.xrpl_mpt_issuance_id === published.xrpl_mpt_issuance_id &&
    // The settlement account belongs in this list for the same reason as the
    // issuance: a config that named a different account would accept settlements
    // debited from somewhere other than the published aggregate account, and
    // labeling that "production" is exactly the confusion this guard prevents.
    config.xrpl_settlement_account === published.xrpl_settlement_account &&
    config.xrpl_token_symbol === published.xrpl_token_symbol &&
    config.xrpl_action_name === published.xrpl_action_name &&
    // The rules domain's signature profile, subject profiles and registered
    // bootstrap statement define what a production verdict accepts as much as
    // the accounts above do.
    config.signature_profile === published.signature_profile &&
    config.foundation_statement_id === published.foundation_statement_id &&
    config.foundation_payload_digest === published.foundation_payload_digest &&
    config.admitted_subject_profiles.length ===
      published.admitted_subject_profiles.length &&
    config.admitted_subject_profiles.every(
      (p, i) => p === published.admitted_subject_profiles[i]
    ) &&
    config.settlement_profile_id === published.settlement_profile_id &&
    Array.isArray(config.supported_rules_versions) &&
    config.supported_rules_versions.length ===
      published.supported_rules_versions.length &&
    config.supported_rules_versions.every(
      (v, i) => v === published.supported_rules_versions[i]
    ) &&
    // The corpus commitment belongs here for the same reason as the settlement
    // account: a config carrying a different subtree_root would accept a corpus
    // other than the published one as the rules text, and calling that
    // "production" is the confusion this guard exists to prevent. Every supported
    // rules version must carry one — a version listed with no commitment is not a
    // production profile (rules-domain/1 §13.3.1).
    config.supported_rules_versions.every(
      (v) =>
        typeof config.rules_corpus_roots?.[v] === "string" &&
        config.rules_corpus_roots[v] === published.rules_corpus_roots[v]
    );
  if (!isProductionProfile) {
    builder.markNonProductionVerification();
  }

  // Step 1: Input validation
  const { proceed, loadedArtifacts } = validateInput(request, builder);
  if (!proceed || !loadedArtifacts) {
    return builder.build();
  }

  // Step 2: Target resolution
  const target = resolveTarget(
    request.verification_target_requested,
    loadedArtifacts,
    builder
  );
  if (!target) {
    return builder.build();
  }
  builder.setResolvedTarget(target);

  // BASE_CERTIFICATE_PRESENT is an artifact-presence check, not an input-mode
  // combination check. Resolve the target first so `auto` still reports the
  // Independent path when proof or settlement material was supplied, then stop
  // as INCOMPLETE because the certificate needed by every route is absent.
  if (!loadedArtifacts.baseCertificate) {
    builder.fail(
      "BASE_CERTIFICATE_PRESENT",
      "INCOMPLETE",
      "base_certificate is absent"
    );
    builder.addMissingArtifact("base_certificate");
    builder.markEarlyExit();
    return builder.build();
  }
  builder.pass("BASE_CERTIFICATE_PRESENT");

  // Record per-subject verdict scope from the base certificate anchor, so the
  // result surfaces WHAT each subject covers (a single opaque input vs a declared
  // collection). Closes the "proving a container proves its children" over-read.
  const anchorSubjects = loadedArtifacts.baseCertificate?.payload?.anchor?.subjects;
  if (Array.isArray(anchorSubjects)) {
    builder.setSubjectScope(
      anchorSubjects.map((s) => (typeof s?.profile === "string" ? s.profile : "unknown"))
    );
  }

  // The profile's own bootstrap statement stands in when the request supplies
  // none. It is validated below exactly like a supplied one.
  if (!loadedArtifacts.systemFoundation && config.foundation_statement) {
    loadedArtifacts.systemFoundation = config.foundation_statement;
  }

  // Step 3: Foundation validation (if system_foundation is present)
  //
  // Per system-foundation/1 and system-domain/1:
  // The foundation is a materialization of the published bootstrap, NOT a
  // replacement. It must be internally coherent (fingerprint = SHA3-256(JCS(
  // system_manifest)), bootstrap quorum statement_signatures valid), AND its
  // derived fingerprint must match the published bootstrap for the rules_version.
  //
  // The foundation does NOT override config.system_root_fingerprint.
  if (loadedArtifacts.systemFoundation) {
    const rulesVersion =
      loadedArtifacts.independenceProof?.rules_version ?? null;
    const derivedFingerprint = verifyFoundation(
      loadedArtifacts.systemFoundation,
      config,
      builder
    );
    if (derivedFingerprint === null) {
      // Foundation present but internally invalid — fail-closed
      return builder.build();
    }
    // FOUNDATION_BOOTSTRAP_MATCHES_RULES:
    // The foundation-derived fingerprint MUST match the published bootstrap
    // exactly. A valid but non-matching foundation is NOT a valid CERTCRYPT
    // domain materialization for this rules_version.
    if (derivedFingerprint !== config.system_root_fingerprint) {
      builder.fail(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
        "REJECTED",
        `Foundation root fingerprint does not match published bootstrap ` +
          `for ${rulesVersion ?? "current rules"}: ` +
          `expected="${config.system_root_fingerprint}", got="${derivedFingerprint}"`
      );
      return builder.build();
    }
    // The registered bootstrap is one exact statement: a statement with the
    // right root but another `foundation_statement_id` is not the one the
    // registry entry declares.
    const statementId = loadedArtifacts.systemFoundation.foundation_statement_id;
    if (statementId !== config.foundation_statement_id) {
      builder.fail(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
        "REJECTED",
        `Foundation statement id does not match the registered bootstrap: ` +
          `expected="${config.foundation_statement_id}", got="${statementId}"`
      );
      return builder.build();
    }
    // ...and one exact signed payload: a second statement over the same manifest
    // and id, even one the bootstrap quorum signed, is not the registered one.
    const payloadDigest = foundationPayloadDigest(loadedArtifacts.systemFoundation);
    if (payloadDigest !== config.foundation_payload_digest) {
      builder.fail(
        "FOUNDATION_BOOTSTRAP_MATCHES_RULES",
        "REJECTED",
        `Foundation statement payload does not match the registered bootstrap: ` +
          `expected digest="${config.foundation_payload_digest}", got="${payloadDigest}"`
      );
      return builder.build();
    }
    builder.pass("FOUNDATION_BOOTSTRAP_MATCHES_RULES");
  }

  // Step 4: Package context (if applicable). Its structure was checked with
  // the input, before any member was read out of it.
  if (
    request.input_mode === "package" &&
    loadedArtifacts.verificationPackage
  ) {
    verifyPackageContext(loadedArtifacts.verificationPackage, builder);
    if (builder.hasFailure()) {
      return builder.build();
    }
  }

  // Step 5: Issued checks (always run, per section 11.2 step 3)
  verifyIssued(loadedArtifacts, config, builder);
  if (builder.hasFailure() && target === "Issued") {
    return builder.build();
  }
  // A certificate that is not Issued-valid cannot be Independent, and the
  // Independent route does not run over it (section 11.2): its checks would
  // only restate the certificate's defect under other names. The comparison
  // against original material is a separate plane and does not stop it.
  if (
    builder.hasFailed("BASE_CERTIFICATE_STRUCTURE_VALID") ||
    builder.hasFailed("BASE_CERTIFICATE_AUTHENTIC")
  ) {
    return builder.build();
  }

  // Step 6: Independent checks (only if target is Independent)
  if (target === "Independent") {
    verifyIndependent(loadedArtifacts, config, builder);
  }

  return builder.build();
}
