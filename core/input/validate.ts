import type { VerifierRequest, LoadedArtifacts } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { loadArtifacts } from "./load-artifacts.js";
import { verifyPackageStructure } from "../package/verify-package.js";

/** Artifacts a request may name one by one; in package mode the package carries them. */
const SEPARATE_ARTIFACTS = [
  "base_certificate",
  "independence_proof",
  "settlement_material",
  "capacity_evidence",
  "commitment_inclusion_proof",
] as const;

const VALID_TARGETS = ["auto", "issued", "independent"];
const VALID_MODES = ["package", "artifact_set"];

export interface InputValidationResult {
  proceed: boolean;
  loadedArtifacts: LoadedArtifacts | null;
}

export function validateInput(
  request: VerifierRequest,
  builder: ResultBuilder
): InputValidationResult {
  // INPUT_TARGET_SUPPORTED
  if (!VALID_TARGETS.includes(request.verification_target_requested)) {
    builder.fail(
      "INPUT_TARGET_SUPPORTED",
      "UNSUPPORTED",
      `Unsupported verification target: ${request.verification_target_requested}`
    );
    builder.markEarlyExit();
    return { proceed: false, loadedArtifacts: null };
  }
  builder.pass("INPUT_TARGET_SUPPORTED");

  // INPUT_MODE_SUPPORTED
  if (!VALID_MODES.includes(request.input_mode)) {
    builder.fail(
      "INPUT_MODE_SUPPORTED",
      "UNSUPPORTED",
      `Unsupported input mode: ${request.input_mode}`
    );
    builder.markEarlyExit();
    return { proceed: false, loadedArtifacts: null };
  }
  builder.pass("INPUT_MODE_SUPPORTED");

  // INPUT_COMBINATION_VALID — each artifact may arrive as a path OR in memory
  // (see VerifierRequest). This check rejects contradictory sources; absence is
  // classified by the artifact's own presence check after target resolution.
  if (
    request.input_mode === "package" &&
    !request.verification_package_path &&
    request.verification_package === undefined
  ) {
    builder.fail(
      "INPUT_COMBINATION_VALID",
      "REJECTED",
      "input_mode is 'package' but neither verification_package nor verification_package_path was supplied"
    );
    builder.markEarlyExit();
    return { proceed: false, loadedArtifacts: null };
  }
  // One source per artifact. In package mode the package is that source, so an
  // artifact also named beside it is a second, possibly different, copy; in
  // artifact-set mode a package beside the artifacts is the same ambiguity.
  // Neither is resolved by picking one (verifier-toolkit/1 §6).
  const req = request as unknown as Record<string, unknown>;
  const named = (k: string) => req[k] !== undefined || req[`${k}_path`] !== undefined;
  if (request.input_mode === "package") {
    const beside = SEPARATE_ARTIFACTS.filter(named);
    if (beside.length > 0) {
      builder.fail(
        "INPUT_COMBINATION_VALID",
        "REJECTED",
        `input_mode is 'package' but ${beside.join(", ")} was also supplied outside the package`
      );
      builder.markEarlyExit();
      return { proceed: false, loadedArtifacts: null };
    }
  } else if (named("verification_package")) {
    builder.fail(
      "INPUT_COMBINATION_VALID",
      "REJECTED",
      "input_mode is 'artifact_set' but a verification_package was also supplied"
    );
    builder.markEarlyExit();
    return { proceed: false, loadedArtifacts: null };
  }
  builder.pass("INPUT_COMBINATION_VALID");

  // Load artifacts
  let artifacts: LoadedArtifacts;
  try {
    artifacts = loadArtifacts(request);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("Duplicate key")) {
      builder.fail(
        "INPUT_COMBINATION_VALID",
        "REJECTED",
        `JSON parsing failed: ${msg}`
      );
    } else {
      builder.fail(
        "INPUT_COMBINATION_VALID",
        "REJECTED",
        `Failed to load artifacts: ${msg}`
      );
    }
    builder.markEarlyExit();
    return { proceed: false, loadedArtifacts: null };
  }

  // PACKAGE_STRUCTURE_VALID — before anything is read out of the package.
  if (request.input_mode === "package") {
    if (!verifyPackageStructure(artifacts.verificationPackage, builder)) {
      builder.markEarlyExit();
      return { proceed: false, loadedArtifacts: artifacts };
    }
  }

  return { proceed: true, loadedArtifacts: artifacts };
}
