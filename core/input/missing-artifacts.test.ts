import { test } from "node:test";
import assert from "node:assert/strict";

import { verify } from "../verify-node.js";

test("an artifact set without its base certificate is incomplete, not rejected", () => {
  const result = verify({
    verification_target_requested: "auto",
    input_mode: "artifact_set",
    independence_proof: {
      proof_version: "independence.proof/1",
      system_id: "certcrypt",
      rules_version: "rules/2026-01",
    } as never,
    settlement_material: {
      settlement_profile_id: "settlement.aggregated.xrpl/1",
      settlement_action: {},
      finality_proof: {},
    } as never,
  });

  assert.equal(result.result_code, "INCOMPLETE");
  assert.equal(result.verification_target, "Independent");
  assert.deepEqual(result.failed_check_ids, ["BASE_CERTIFICATE_PRESENT"]);
  assert.deepEqual(result.required_artifacts_missing, ["base_certificate"]);
  assert.equal(result.failure_reason, "base_certificate is absent");
});

test("an empty artifact set reports the same missing certificate on the Issued path", () => {
  const result = verify({
    verification_target_requested: "auto",
    input_mode: "artifact_set",
  });

  assert.equal(result.result_code, "INCOMPLETE");
  assert.equal(result.verification_target, "Issued");
  assert.deepEqual(result.failed_check_ids, ["BASE_CERTIFICATE_PRESENT"]);
  assert.deepEqual(result.required_artifacts_missing, ["base_certificate"]);
});
