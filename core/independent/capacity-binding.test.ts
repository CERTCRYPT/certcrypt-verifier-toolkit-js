/**
 * Tests for the capacity-evidence binding check.
 *
 * Reuses the golden-e2e fixture (real evidence + system-domain pubkey, produced
 * by the reference producer). In the zero-data profile a commitment's id IS its
 * evidence digest (`capacity.evidence/1`), so the binding ties the evidence
 * to the `commitment_id` carried in the evaluated certificate's inclusion path.
 */

import { PROFILE_P256_MLDSA65 } from "../crypto/composite.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCapacityBinding } from "./capacity-binding.js";
import { ResultBuilder } from "../result/builder.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { IndependenceProof } from "../types/proof.js";
import type { CommitmentInclusionProof } from "../types/settlement-material.js";
import type { SystemFoundation } from "../types/foundation.js";
import type { VerifierRequest } from "../types/request.js";

const here = dirname(fileURLToPath(import.meta.url));
const GOLDEN = join(
  here,
  "..",
  "..",
  "..",
  "..",
  "certcrypt-conformance",
  "fixtures",
  "primitives",
  "capacity-evidence",
  "golden-e2e.json"
);

const REQ: VerifierRequest = {
  verification_target_requested: "independent",
  input_mode: "artifact_set",
};

/** Minimal proof; the binding check reads nothing digest-specific off it. */
function proof(): IndependenceProof {
  return {
    proof_version: "independence.proof/1",
    system_id: "certcrypt",
    system_root_fingerprint: "00".repeat(32),
    rules_version: "rules/conformance",
    subtree_root: "11".repeat(32),
    settlement_ref: "x",
    settlement: { profile_id: "settlement.aggregated.xrpl/1" } as never,
    batch: { root: "22".repeat(32), index: "0", size: "1" } as never,
    inclusion_proof: [],
    anti_replay: { nonce: "n", derivation: "d" } as never,
    independence_result: "independent",
    proof_id: "33".repeat(32),
    closure_time: "2026-04-11T12:00:00Z",
    consumed_commitment_ids: ["44".repeat(32)],
    proof_digest: "55".repeat(32),
    signature: { signing_kid: "k", alg: "a", mode: "m", signatures: [] },
  };
}

/** Inclusion proof carrying the evaluated certificate's commitment_id. */
function inclusion(commitmentId: string): CommitmentInclusionProof {
  return {
    commitment_id: commitmentId,
    commitment_leaf_hash: "33".repeat(32),
    commitment_index: "0",
    commitment_siblings: [],
    subtree_size: "1",
  } as CommitmentInclusionProof;
}

function foundation(mldsaB64: string, classicalB64: string): SystemFoundation {
  return {
    system_root_fingerprint: "00".repeat(32),
    // capacity-binding verifies the evidence's composite L1 anchor against
    // BOTH component keys of the system-domain Level-1 key (classical + ML-DSA).
    system_domain_capacity_key_mldsa_b64: mldsaB64,
    system_domain_capacity_key_p256_b64: classicalB64,
  } as SystemFoundation;
}

function loadGolden() {
  if (!existsSync(GOLDEN)) return null;
  return JSON.parse(readFileSync(GOLDEN, "utf-8"));
}

test("evidence whose digest equals the commitment_id -> CAPACITY_EVIDENCE_VALID passes", async () => {
  const g = loadGolden();
  if (!g) {
    console.error("golden-e2e.json not found; skipping");
    return;
  }
  assert.ok(await initMlDsa65(), "@noble/post-quantum required");

  const builder = new ResultBuilder(REQ);
  verifyCapacityBinding(
    proof(),
    g.evidence,
    inclusion(g.expected_evidence_digest),
    foundation(g.system_domain_mldsa_public_key_b64, g.system_domain_p256_public_key_b64),
    builder, PROFILE_P256_MLDSA65);
  assert.equal(builder.hasFailure(), false, "binding must pass when evidence digest == commitment_id");
});

test("commitment present but NO evidence -> fail-closed", () => {
  const g = loadGolden();
  if (!g) return;
  const builder = new ResultBuilder(REQ);
  verifyCapacityBinding(
    proof(),
    null,
    inclusion(g.expected_evidence_digest),
    foundation(g.system_domain_mldsa_public_key_b64, g.system_domain_p256_public_key_b64),
    builder, PROFILE_P256_MLDSA65);
  assert.equal(builder.hasFailure(), true, "a consumed commitment with no backing evidence must fail closed");
});

test("evidence digest != commitment_id -> fail-closed", async () => {
  const g = loadGolden();
  if (!g) return;
  await initMlDsa65();
  const builder = new ResultBuilder(REQ);
  // The inclusion path carries a DIFFERENT commitment_id than the evidence
  // recomputes to (spliced evidence).
  verifyCapacityBinding(
    proof(),
    g.evidence,
    inclusion("ff".repeat(32)),
    foundation(g.system_domain_mldsa_public_key_b64, g.system_domain_p256_public_key_b64),
    builder, PROFILE_P256_MLDSA65);
  assert.equal(builder.hasFailure(), true, "evidence not matching the commitment_id must fail closed");
});

test("no commitment inclusion proof -> fail-closed (cannot bind)", () => {
  const g = loadGolden();
  if (!g) return;
  const builder = new ResultBuilder(REQ);
  verifyCapacityBinding(proof(), g.evidence, null, foundation(g.system_domain_mldsa_public_key_b64, g.system_domain_p256_public_key_b64), builder, PROFILE_P256_MLDSA65);
  assert.equal(builder.hasFailure(), true, "no commitment to bind the evidence to must fail closed");
});
