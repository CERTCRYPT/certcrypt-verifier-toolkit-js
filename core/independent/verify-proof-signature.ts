/**
 * Verify the IndependenceProof signature against the CERTCRYPT system domain.
 *
 * Check: PROOF_SIGNATURE_VALID.
 *
 * The signature is MANDATORY under every rules domain (independence.proof/1
 * §10.13): a composite under the rules domain's signature profile (ECDSA P-256
 * + ML-DSA-65, classical first) by the system-domain Level-1 capacity key the
 * system foundation publishes, over the JCS of the signed view (§10.13.1). An
 * absent signature, an unresolvable signer key or an unavailable ML-DSA-65
 * runtime fail closed; none of them is reported as "not performed".
 *
 * The signed view carries `anti_replay` and, when present, `node_attestation`,
 * so a passing signature also authenticates the node attestation.
 */

import type {
  IndependenceProof,
  ProofSignature,
  SystemFoundation,
} from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { digestHexBytes } from "../crypto/digest.js";
import { verifyComposite } from "../crypto/composite.js";
import { proofSignedView } from "./proof-views.js";

/** The proof signature's closed member set (independence.proof/1 §10.13). */
const PROOF_SIGNATURE_MEMBERS = ["signing_kid", "alg", "mode", "signatures"];

function isProofSignatureObject(s: unknown): s is ProofSignature {
  if (typeof s !== "object" || s === null || Array.isArray(s)) return false;
  const keys = Object.keys(s);
  return (
    keys.length === PROOF_SIGNATURE_MEMBERS.length &&
    PROOF_SIGNATURE_MEMBERS.every((m) => Object.hasOwn(s, m)) &&
    typeof (s as ProofSignature).signing_kid === "string" &&
    (s as ProofSignature).signing_kid.length > 0 &&
    typeof (s as ProofSignature).alg === "string" &&
    Array.isArray((s as ProofSignature).signatures)
  );
}

export function verifyProofSignature(
  proof: IndependenceProof,
  foundation: SystemFoundation | null,
  builder: ResultBuilder,
  /** The composite profile the rules domain fixes for the proof signature. */
  signatureProfile: string,
): void {
  const sig: unknown = proof.signature;

  // Absent → the signed fields carry no authenticity: incomplete. Present but not
  // a composite signature object → malformed: rejected.
  if (sig === undefined || sig === null) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "INCOMPLETE",
      "independence_proof carries no signature; it is mandatory",
    );
    builder.addMissingArtifact("proof_signature");
    return;
  }
  if (!isProofSignatureObject(sig)) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "REJECTED",
      "independence_proof signature is not a composite signature object with exactly " +
        PROOF_SIGNATURE_MEMBERS.join(", "),
    );
    return;
  }

  // The expected profile is the rules domain's, never the one the signature
  // declares: a proof signed under another profile fails even if it verifies.
  if (sig.alg !== signatureProfile) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "REJECTED",
      `proof signature profile "${sig.alg}" is not the rules domain's "${signatureProfile}"`,
    );
    return;
  }

  // The proof is signed by the system-domain Level-1 COMPOSITE key — the DISTINCT
  // capacity key (NOT the bootstrap root, which signs the foundation statement).
  // Both component public keys are published in the foundation. Without them the
  // verifier cannot resolve the signer key offline: incomplete.
  const mldsaPub = foundation?.system_domain_capacity_key_mldsa_b64;
  const classicalPub = foundation?.system_domain_capacity_key_p256_b64;
  if (!foundation || !mldsaPub || !classicalPub) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "INCOMPLETE",
      "no complete system-domain composite capacity key is available from system_foundation to verify the proof signature",
    );
    builder.addMissingArtifact("system_foundation");
    return;
  }

  // Defense in depth: the proof must be bound to the same root the foundation
  // attests, so a proof from a cloned domain cannot be verified with this domain's key.
  if (
    proof.system_root_fingerprint &&
    foundation.system_root_fingerprint &&
    proof.system_root_fingerprint !== foundation.system_root_fingerprint
  ) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "INDEPENDENT_INVALID",
      "proof system_root_fingerprint does not match the system_foundation root",
    );
    return;
  }

  // Composite signs M' = composite_m_prime(SHA3-256(JCS(signed view))).
  const signingBytes = jcsCanonicalizeBytes(proofSignedView(proof));
  const signingDigestHex = digestHexBytes(signingBytes);
  const result = verifyComposite(
    signatureProfile,
    signingDigestHex,
    { alg: sig.alg, mode: sig.mode, signatures: sig.signatures },
    { classicalPubB64: classicalPub, mldsaPubB64: mldsaPub },
  );

  // Malformed material — layout, members, fixed values, key encoding — is a
  // structural defect, not a signature that fails to verify.
  if (result.malformed) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "REJECTED",
      `proof composite signature is malformed: ${result.malformed}`,
    );
    return;
  }
  if (result.mldsa.performed === false && (result.mldsa.reason ?? "").startsWith("unsupported_runtime")) {
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "UNSUPPORTED",
      `ML-DSA-65 verification is unavailable, so the mandatory proof signature cannot be verified: ${result.mldsa.reason}`,
    );
    return;
  }
  if (!result.valid) {
    const why = result.mldsa.passed !== true
      ? `ML-DSA-65 component (${result.mldsa.reason})`
      : `${result.classical.alg ?? "classical"} component (${result.classical.reason})`;
    builder.fail(
      "PROOF_SIGNATURE_VALID",
      "INDEPENDENT_INVALID",
      `proof composite signature does not verify against the system-domain key: ${why}`,
    );
    return;
  }

  builder.pass("PROOF_SIGNATURE_VALID");
}
