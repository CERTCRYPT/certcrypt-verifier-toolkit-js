import { getFileSystemBridge } from "./fs-bridge.js";
import type {
  VerifierRequest,
  LoadedArtifacts,
  BaseCertificate,
  IndependenceProof,
  SettlementMaterial,
  VerificationPackage,
  SystemFoundation,
} from "../types/index.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import type { CommitmentInclusionProof } from "../types/settlement-material.js";
import { strictJsonParse } from "./strict-json.js";
import { loadOriginalMaterial } from "./load-original-material.js";

/**
 * Resolve one artifact: the in-memory value wins, else the file is read and
 * strict-parsed, else null.
 *
 * The precedence is deliberate and one-directional — an in-memory artifact is
 * something the caller already holds, so re-reading a path it also passed would
 * silently ignore what it handed us. Neither form is deprecated: the CLI reads
 * files, a service passes objects.
 */
function resolve<T>(inMemory: T | undefined, path: string | undefined): T | null {
  if (inMemory !== undefined) return inMemory;
  if (!path) return null;
  return strictJsonParse(getFileSystemBridge().readTextFile(path)) as T;
}

export function loadArtifacts(request: VerifierRequest): LoadedArtifacts {
  const result: LoadedArtifacts = {
    baseCertificate: null,
    independenceProof: null,
    settlementMaterial: null,
    capacityEvidence: null,
    commitmentInclusionProof: null,
    verificationPackage: null,
    originalMaterialPath: request.original_material_path ?? null,
    // The subject-material map is loaded from originalMaterialPath by
    // loadOriginalMaterial below (delivery container). Null means no
    // material was supplied → the complete-verification plane is not performed;
    // the structural Independent/Issued result still stands.
    originalMaterial: null,
    systemFoundation: null,
  };

  const pkgIn = resolve<VerificationPackage>(
    request.verification_package,
    request.verification_package_path
  );
  if (request.input_mode === "package" && pkgIn !== null) {
    // Kept as delivered: PACKAGE_STRUCTURE_VALID decides whether it is a package
    // at all before any member below is used.
    result.verificationPackage = pkgIn;
    const pkg = pkgIn as unknown as Record<string, unknown>;
    if (typeof pkg === "object" && !Array.isArray(pkg)) {
      result.baseCertificate = (pkg.base_certificate as BaseCertificate | undefined) ?? null;
      result.independenceProof = (pkg.independence_proof as IndependenceProof | undefined) ?? null;
      result.settlementMaterial = (pkg.settlement_material as SettlementMaterial | undefined) ?? null;
      result.capacityEvidence = (pkg.capacity_evidence as CapacityEvidence | undefined) ?? null;
      result.commitmentInclusionProof =
        (pkg.commitment_inclusion_proof as CommitmentInclusionProof | undefined) ?? null;
    }
  }

  if (request.input_mode === "artifact_set") {
    result.baseCertificate = resolve<BaseCertificate>(
      request.base_certificate,
      request.base_certificate_path
    );

    result.independenceProof = resolve<IndependenceProof>(
      request.independence_proof,
      request.independence_proof_path
    );

    result.settlementMaterial = resolve<SettlementMaterial>(
      request.settlement_material,
      request.settlement_material_path
    );

    result.capacityEvidence = resolve<CapacityEvidence>(
      request.capacity_evidence,
      request.capacity_evidence_path
    );

    result.commitmentInclusionProof = resolve<CommitmentInclusionProof>(
      request.commitment_inclusion_proof,
      request.commitment_inclusion_proof_path
    );
  }

  // The system foundation is never a package member: it is public rules
  // material the verifier obtains itself, pinned by the
  // foundation_statement_id and root fingerprint of its configuration
  // (verifier-toolkit/1 §8.2), in either mode.
  result.systemFoundation = resolve<SystemFoundation>(
    request.system_foundation,
    request.system_foundation_path
  );

  // Verifier-local original material (optional, both modes). The path points at
  // a subject-material manifest (delivery container); loaded into the
  // index → bytes map the complete-verification plane consumes.
  // In-memory wins, as everywhere above. A bare Uint8Array is accepted as
  // shorthand for the single-subject case (index 0) — the common shape by far,
  // and spelling out `new Map([[0, bytes]])` for it is noise.
  if (request.original_material !== undefined) {
    result.originalMaterial =
      request.original_material instanceof Uint8Array
        ? new Map([[0, request.original_material]])
        : request.original_material;
  } else if (request.original_material_path) {
    result.originalMaterial = loadOriginalMaterial(request.original_material_path);
  }

  return result;
}
