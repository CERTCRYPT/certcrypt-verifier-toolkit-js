// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * `verifySettlement` against the published conformance material.
 *
 * This module recomputes two preimages field by field — the batch binding and the
 * settlement leaf — with the order written out by hand. That order is a byte
 * contract shared with a PRODUCER WRITTEN IN ANOTHER LANGUAGE (the reference
 * producer that emits the material). Nothing here fails if the two drift: the digest
 * simply stops matching, and the first symptom is a real emission that will not
 * verify.
 *
 * So these tests do two things a structural test would not:
 *
 *   - drive the check with REAL material from `certcrypt-conformance`, so the
 *     field order is pinned against what the producer actually emits;
 *   - move one field at a time and require the verdict to change, so a
 *     reordering cannot pass unnoticed.
 *
 * The fixtures are not vendored here — the contract is versioned separately and a
 * copy would drift. Absent the sibling checkout these tests skip with a message
 * naming what to check out.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { MANIFEST_ANCHORED_FIELDS, verifySettlement } from "./settlement.js";
import { ResultBuilder } from "../result/builder.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import type { IndependenceProof } from "../types/proof.js";
import type { SettlementMaterial } from "../types/settlement-material.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import type { VerifierRequest } from "../types/request.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(
  here, "..", "..", "..", "..",
  "certcrypt-conformance", "fixtures", "conformance", "P001", "artifacts"
);

const available = existsSync(FIXTURE);
const skip = available
  ? false
  : `conformance fixtures not found: check out certcrypt-conformance as a sibling of this repository (looked for ${FIXTURE})`;

const REQ: VerifierRequest = {
  verification_target_requested: "independent",
  input_mode: "artifact_set",
};

const load = <T>(name: string): T =>
  JSON.parse(readFileSync(join(FIXTURE, name), "utf-8")) as T;

/** Fresh copies per test: every case mutates its own material. */
function artifacts(): {
  proof: IndependenceProof;
  material: SettlementMaterial;
  evidence: CapacityEvidence;
} {
  return {
    proof: load<IndependenceProof>("independence-proof.json"),
    material: load<SettlementMaterial>("settlement-material.json"),
    // The bridge anchors to the capacity evidence, so settlement cannot be
    // verified without it — passing null here would fail for a reason that has
    // nothing to do with what these tests are checking.
    evidence: load<CapacityEvidence>("capacity-evidence.json"),
  };
}

function run(
  proof: IndependenceProof,
  material: SettlementMaterial,
  evidence: CapacityEvidence
): ResultBuilder {
  const builder = new ResultBuilder(REQ);
  verifySettlement(proof, material, evidence, getConformanceConfig(), builder);
  return builder;
}

/**
 * The checks this module is responsible for.
 *
 * `verifySettlement` is a partial verifier: the input and certificate phases run
 * elsewhere, so `build()` also reports those as "not executed". Filtering to this
 * set keeps the assertions about settlement rather than about what the harness
 * did not run.
 *
 * The set is deliberately broader than one id: tampering surfaces under different
 * ids depending on WHERE it breaks the chain — a changed batch field fails
 * `CAPACITY_NOT_RECONSTRUCTED`, a swapped profile fails `SETTLEMENT_REF_VALID`.
 * Asserting on a single id would let a rejection for the "wrong" reason read as
 * a pass.
 */
const SETTLEMENT_CHECKS = new Set([
  "SETTLEMENT_REF_VALID",
  "CAPACITY_BINDING_VALID",
  "CAPACITY_NOT_RECONSTRUCTED",
  "INCLUSION_PROOF_VALID",
  "FINALITY_SUFFICIENT",
  "SETTLEMENT_NOT_RETROACTIVE",
  "AGGREGATED_INTERPRETATION_UNIQUE",
  "COMMITMENT_TTL_VALID",
]);

/** Did every settlement-owned check pass? */
function settlementOk(builder: ResultBuilder): boolean {
  return !builder
    .build()
    .failed_check_ids.some((id) => SETTLEMENT_CHECKS.has(id));
}

describe("verifySettlement", { skip }, () => {
  it("accepts the published settlement material unchanged", () => {
    const { proof, material, evidence } = artifacts();
    assert.ok(
      settlementOk(run(proof, material, evidence)),
      "the real material from P001 must verify — if this fails, the recomputation " +
        "in settlement.ts has drifted from what the producer emits"
    );
  });

  it("rejects a batch binding whose fields were reordered", () => {
    // Same values, different member order. JSON.parse preserves insertion order,
    // so rebuilding the object reversed is enough to change the serialized bytes
    // IF the implementation serialized the object as given. It must not: the
    // digest is computed over a FIXED field order, so this has to still verify.
    const { proof, material, evidence } = artifacts();
    const bbp = material.authorization_bridge_proofs![0].batch_binding_preimage as unknown as Record<string, unknown>;
    const reversed: Record<string, unknown> = {};
    for (const k of Object.keys(bbp).reverse()) reversed[k] = bbp[k];
    material.authorization_bridge_proofs![0].batch_binding_preimage = reversed as never;

    assert.ok(
      settlementOk(run(proof, material, evidence)),
      "member order in the delivered JSON must not affect the digest: the " +
        "implementation pins the field order itself"
    );
  });

  it("rejects a batch binding with a tampered value", () => {
    const { proof, material, evidence } = artifacts();
    const bbp = material.authorization_bridge_proofs![0].batch_binding_preimage as unknown as Record<string, unknown>;
    bbp.total_quantity = "999999.00";
    assert.ok(
      !settlementOk(run(proof, material, evidence)),
      "a changed field must break the memo digest and fail the check"
    );
  });

  it("rejects a settlement root that does not match the memo", () => {
    const { proof, material, evidence } = artifacts();
    const bbp = material.authorization_bridge_proofs![0].batch_binding_preimage as unknown as Record<string, unknown>;
    bbp.settlement_root = "ff".repeat(32);
    assert.ok(!settlementOk(run(proof, material, evidence)));
  });

  it("rejects a tampered leaf preimage", () => {
    const { proof, material, evidence } = artifacts();
    const lp = material.submission_assignment_proof!.leaf_preimage as unknown as Record<string, unknown>;
    lp.consumed_quantity = "999.00";
    assert.ok(
      !settlementOk(run(proof, material, evidence)),
      "the leaf hash is recomputed from the preimage; a changed field must not pass"
    );
  });

  it("rejects a leaf preimage whose settlement_profile_id was swapped", () => {
    // The profile is INSIDE the signed preimage on purpose: a leaf from one
    // substrate must not replant in another.
    const { proof, material, evidence } = artifacts();
    const lp = material.submission_assignment_proof!.leaf_preimage as unknown as Record<string, unknown>;
    lp.settlement_profile_id = "some.other.substrate/1";
    assert.ok(!settlementOk(run(proof, material, evidence)));
  });

  it("rejects a settlement debited from a foreign account", () => {
    // Unlinkability: every settlement in a window debits the SAME aggregate
    // account, so an observer sees one burn and cannot tell which issuer
    // certified. A settlement from an issuer's own account would put that
    // identity on the public ledger — and would also let a holder claim capacity
    // it never pooled.
    const { proof, material, evidence } = artifacts();
    const tampered = structuredClone(material);
    tampered.settlement_action.from = "rATTACKERaccountXXXXXXXXXXXXXXXXXX";
    assert.ok(
      !settlementOk(run(proof, tampered, evidence)),
      "a settlement debited from an account other than the published settlement " +
        "account must be rejected"
    );
  });

  it("rejects a memo that does not carry the expected prefix", () => {
    const { proof, material, evidence } = artifacts();
    material.settlement_action!.memo = `wrong:${"ab".repeat(32)}`;
    assert.ok(!settlementOk(run(proof, material, evidence)));
  });

  it("rejects a profile other than the required one", () => {
    const { proof, material, evidence } = artifacts();
    proof.settlement.profile_id = "some.other.profile/1" as never;
    assert.ok(!settlementOk(run(proof, material, evidence)));
  });

  it("fails closed when the settlement material is absent", () => {
    const { proof, evidence } = artifacts();
    const builder = new ResultBuilder(REQ);
    verifySettlement(proof, null, evidence, getConformanceConfig(), builder);
    assert.ok(
      !settlementOk(builder),
      "absent material is not an absent constraint"
    );
  });

  it("decides finality offline and only from canonical ledger numbers", () => {
    // settlement.aggregated.xrpl/1 §11.3: canonical non-negative decimals, the
    // observed validated ledger not before the inclusion ledger, both hashes
    // present. Nothing here can reach the network, so a pass is offline by
    // construction.
    const failsFinality = (mutate: (fp: Record<string, unknown>) => void) => {
      const { proof, material, evidence } = artifacts();
      mutate(material.finality_proof as unknown as Record<string, unknown>);
      return run(proof, material, evidence)
        .build()
        .failed_check_ids.includes("FINALITY_SUFFICIENT");
    };
    for (const bad of ["+5", "007", "12abc", "-1", "", "1.0"]) {
      assert.ok(failsFinality((fp) => (fp.block_num = bad)), `block_num ${JSON.stringify(bad)}`);
    }
    assert.ok(
      failsFinality((fp) => {
        fp.last_irreversible_block_num = String(Number(fp.block_num) - 1);
      }),
      "an observed ledger before the inclusion ledger is not final"
    );
    assert.ok(failsFinality((fp) => (fp.block_id = "")), "block_id must be present");
    assert.ok(
      failsFinality((fp) => (fp.last_irreversible_block_id = "")),
      "last_irreversible_block_id must be present"
    );
  });

  it("rejects a burn smaller than the anchored total, even with a restated manifest", () => {
    // P001 anchors total_quantity "10.00" in the memo. Burn "5.00" and restate
    // every UNANCHORED copy of the total to match the burn: the action, the
    // consumption proof and batch_manifest agree with each other, but not with
    // what the transaction memo commits to.
    const { proof, material, evidence } = artifacts();
    material.settlement_action!.quantity = "5.00 CERT";
    material.capacity_consumption_proof!.total_quantity = "5.00";
    material.batch_manifest.total_quantity = "5.00";
    const builder = run(proof, material, evidence);
    assert.ok(
      builder.build().failed_check_ids.includes("CAPACITY_BINDING_VALID"),
      "the burned quantity must be compared with the anchored preimage total, " +
        "not with the producer-supplied manifest"
    );
  });

  it("rejects a batch_manifest total that differs from the anchored one", () => {
    // Burn and anchor agree; only the manifest's copy diverges.
    const { proof, material, evidence } = artifacts();
    material.batch_manifest.total_quantity = "11.00";
    const builder = run(proof, material, evidence);
    assert.ok(builder.build().failed_check_ids.includes("CAPACITY_BINDING_VALID"));
  });

  it("checks every field the manifest shares with the anchored preimage", () => {
    // Pinned so a field silently dropped from the derived list is noticed: the
    // type-level derivation only catches fields added to BOTH types.
    assert.deepEqual([...MANIFEST_ANCHORED_FIELDS].sort(), [
      "batch_id",
      "leaf_count",
      "rules_version",
      "settlement_profile_id",
      "settlement_root",
      "system_id",
      "total_quantity",
      "window_id",
    ]);
  });

  for (const field of MANIFEST_ANCHORED_FIELDS) {
    it(`rejects a batch_manifest ${field} that differs from the anchored one`, () => {
      // The anchor, the leaf and the inclusion path are untouched; only the
      // manifest's copy of one anchored field diverges. settlement_root is held
      // to proof.batch.root before the consumption step, so it fails there.
      const { proof, material, evidence } = artifacts();
      material.batch_manifest[field] = `${material.batch_manifest[field]}-restated`;
      const builder = run(proof, material, evidence);
      const want =
        field === "settlement_root" ? "AGGREGATED_INTERPRETATION_UNIQUE" : "CAPACITY_BINDING_VALID";
      const failed = builder.build().failed_check_ids.filter((id) => SETTLEMENT_CHECKS.has(id));
      assert.deepEqual(failed, [want]);
    });
  }

  it("fails closed as incomplete when batch_manifest is absent", () => {
    // The settlement root coherence is three-way (batch_manifest,
    // batch_binding_preimage, proof.batch.root): without the manifest it cannot
    // be established, and the verifier must say so rather than throw.
    const { proof, material, evidence } = artifacts();
    delete (material as Partial<SettlementMaterial>).batch_manifest;
    const builder = run(proof, material, evidence);
    const result = builder.build();
    assert.ok(!settlementOk(builder));
    assert.ok(result.failed_check_ids.includes("AGGREGATED_INTERPRETATION_UNIQUE"));
    assert.ok(result.required_artifacts_missing.includes("batch_manifest"));
  });

  it("requires the bridge proofs to agree on one batch-level binding", () => {
    const { proof, material, evidence } = artifacts();
    const bridges = material.authorization_bridge_proofs!;
    const second = JSON.parse(JSON.stringify(bridges[0]));
    (second.batch_binding_preimage as unknown as Record<string, unknown>).batch_id = "another-batch";
    material.authorization_bridge_proofs = [bridges[0], second];
    assert.ok(
      !settlementOk(run(proof, material, evidence)),
      "two disagreeing bindings must not resolve to whichever came first"
    );
  });
});
