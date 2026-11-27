/**
 * Cross-language verification of a REAL signed IndependenceProofV1.
 * The vector in
 * certcrypt-conformance/fixtures/primitives/independence-proof-signature was
 * produced by the reference proof producer, NOT by this toolkit — so a
 * passing signature proves the TS verifier reconstructs the no-sig signing view
 * and JCS byte-identically to the producer and verifies the ML-DSA-65 signature against
 * the system-domain key. A divergence of a single byte fails to verify.
 *
 * Requires the @noble/post-quantum optional dependency to be installed; if the
 * ML-DSA backend is unavailable the verification is reported "not performed" and
 * the test skips the cryptographic assertion (still exercises the plumbing).
 */

import { PROFILE_P256_MLDSA65 } from "../crypto/composite.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyProofSignature } from "./verify-proof-signature.js";
import { ResultBuilder } from "../result/builder.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type {
  IndependenceProof,
  SystemFoundation,
  VerifierRequest,
} from "../types/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const PRIMITIVES = join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives");

const REQ: VerifierRequest = {
  verification_target_requested: "independent",
  input_mode: "artifact_set",
};

function loadVectors(name: string): any | null {
  const p = join(PRIMITIVES, name, "vectors.json");
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, "utf-8"));
}

/** Minimal foundation carrying the system-domain Level-1 capacity key. The
 * proof-signature path only reads system_domain_capacity_key_*; the embedded
 * manifest/statement_signatures are present for shape but not exercised here. */
function foundationFor(v: any): SystemFoundation {
  return {
    foundation_profile_id: "system-foundation/1",
    foundation_statement_id: "test",
    system_id: v.proof.system_id,
    system_root_fingerprint: v.proof.system_root_fingerprint,
    system_manifest: {
      manifest_profile_id: "system-manifest/1",
      system_id: v.proof.system_id,
      manifest_sequence: 0,
      entries: [
        {
          kid: "test-root",
          algorithm: "certcrypt-composite-p256-mldsa65-v1",
          quorum: { k: 2, n: 2 },
          members: [],
          valid_from: "2026-06-15T12:00:00Z",
          valid_until: null,
          predecessor_kid: null,
          successor_kid: null,
          predecessor_signatures: null,
          predecessor_manifest_fingerprint: null,
        },
      ],
    },
    root_fingerprint_derivation: "sha3-256-system-manifest-jcs-v1",
    published_rules_versions: [v.proof.rules_version],
    statement_issued_at: "2026-06-15T12:00:00Z",
    statement_signatures: [],
    // The proof is signed by the system-domain Level-1 COMPOSITE key (both
    // component public keys are published in the foundation).
    system_domain_capacity_key_mldsa_b64: v.system_domain_mldsa_public_key_b64,
    system_domain_capacity_key_p256_b64: v.system_domain_p256_public_key_b64,
  };
}

function failedSig(builder: ResultBuilder): boolean {
  return builder.build().failed_check_ids.includes("PROOF_SIGNATURE_VALID");
}

test("proof signature: TS verifies the reference producer's real proof signature", async () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) {
    console.error("conformance not found alongside toolkit; skipping");
    return;
  }
  const ready = await initMlDsa65();
  const proof = v.proof as IndependenceProof;
  const foundation = foundationFor(v);

  const builder = new ResultBuilder(REQ);
  verifyProofSignature(proof, foundation, builder, PROFILE_P256_MLDSA65);

  if (!ready) {
    console.error("ML-DSA backend unavailable; skipping cryptographic assertion");
    // Plumbing still ran without throwing.
    return;
  }
  assert.equal(failedSig(builder), false, "the reference producer's real proof signature must verify in TS");
});

test("proof signature: tampering a signed field makes the signature fail", async () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  const ready = await initMlDsa65();
  if (!ready) return;

  // Flip the subtree_root (a signed field) → signature must no longer verify.
  const tampered = { ...v.proof, subtree_root: "00".repeat(32) } as IndependenceProof;
  const builder = new ResultBuilder(REQ);
  verifyProofSignature(tampered, foundationFor(v), builder, PROFILE_P256_MLDSA65);
  assert.equal(failedSig(builder), true, "a tampered signed field must fail the signature check");
});

test("proof signature: a signature declaring another profile fails, whatever it would verify under", () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  // The expected profile is the rules domain's. Relabelling the signature to the
  // other registered profile must fail before any cryptography is attempted.
  const p = v.proof as IndependenceProof;
  const relabelled = {
    ...p,
    signature: { ...(p.signature as object), alg: "certcrypt-composite-ed25519-mldsa65-v1" },
  } as IndependenceProof;
  const builder = new ResultBuilder(REQ);
  verifyProofSignature(relabelled, foundationFor(v), builder, PROFILE_P256_MLDSA65);
  assert.equal(failedSig(builder), true, "a proof signature under a non-admitted profile must fail");
});

test("proof signature: wrong system-domain root fingerprint fails closed", async () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  const foundation = { ...foundationFor(v), system_root_fingerprint: "cd".repeat(32) };
  const builder = new ResultBuilder(REQ);
  verifyProofSignature(v.proof as IndependenceProof, foundation, builder, PROFILE_P256_MLDSA65);
  assert.equal(failedSig(builder), true, "root fingerprint mismatch must fail closed");
});

test("proof signature: no foundation key → fails closed (INCOMPLETE)", () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  const builder = new ResultBuilder(REQ);
  verifyProofSignature(v.proof as IndependenceProof, null, builder, PROFILE_P256_MLDSA65);
  assert.equal(failedSig(builder), true, "without the signer key the mandatory signature cannot verify");
});

test("proof signature: absent signature → fails closed (INCOMPLETE), under any rules domain", () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  const { signature: _omit, ...unsigned } = v.proof;
  const builder = new ResultBuilder(REQ);
  verifyProofSignature(unsigned as IndependenceProof, foundationFor(v), builder, PROFILE_P256_MLDSA65);
  const result = builder.build();
  assert.ok(result.failed_check_ids.includes("PROOF_SIGNATURE_VALID"));
  assert.ok(result.required_artifacts_missing.includes("proof_signature"));
});

test("proof signature: the node attestation and anti_replay are inside the signed view", async () => {
  const v = loadVectors("independence-proof-signature");
  if (!v) return;
  const ready = await initMlDsa65();
  if (!ready) return;
  assert.ok(v.proof.node_attestation, "the vector carries a node attestation");
  for (const tampered of [
    { ...v.proof, node_attestation: { ...v.proof.node_attestation, node_id: "op:QW5vdGhlck5vZGVJZDAwMD" } },
    { ...v.proof, node_attestation: { ...v.proof.node_attestation, recognized_at: "2026-06-15T12:59:59Z" } },
    (() => { const { node_attestation: _n, ...rest } = v.proof; return rest; })(),
    { ...v.proof, anti_replay: { ...v.proof.anti_replay, nonce: "00".repeat(32) } },
  ]) {
    const builder = new ResultBuilder(REQ);
    verifyProofSignature(tampered as IndependenceProof, foundationFor(v), builder, PROFILE_P256_MLDSA65);
    assert.equal(failedSig(builder), true, "altering a signed member must fail the signature");
  }
});
