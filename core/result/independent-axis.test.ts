/**
 * `independent_valid` is an AXIS, not an alias of `result_code`.
 *
 * What this pins: supplying original material for SOME subjects but not all fails
 * ORIGINAL_MATERIAL_COMPARISON_VALID, which makes `result_code` INCOMPLETE
 * (correct — `verifier-toolkit/1` §8.5.1 fixes that outcome so toolkits converge).
 * `independent_valid` must stay true, as `domain_valid`, `rules_domain_valid`,
 * `issued_valid` and `proof_complete` do: if adding information appeared to
 * invalidate independence, it would teach the reader to withhold material for a
 * cleaner answer.
 *
 * ORIGINAL_MATERIAL_COMPARISON_VALID is NOT in INDEPENDENT_REQUIRED_CHECKS: the axis
 * does not depend on material. These tests assert the boolean matches that
 * definition, and — the other half, which matters more — that a REAL
 * failure on the axis still reports false.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ResultBuilder } from "./builder.js";
import type { VerifierRequest, CheckId } from "../types/index.js";

/** Every check the operational Independent path requires, in one place. */
const AXIS: CheckId[] = [
  // ISSUED_REQUIRED_CHECKS is a prefix of the Independent list; omitting these four
  // would make the builder report INCOMPLETE ("required check was not executed") even with
  // every other check passing.
  "INPUT_TARGET_SUPPORTED",
  "INPUT_MODE_SUPPORTED",
  "INPUT_COMBINATION_VALID",
  "BASE_CERTIFICATE_PRESENT",
  "BASE_CERTIFICATE_STRUCTURE_VALID",
  "BASE_CERTIFICATE_AUTHENTIC",
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
  "NON_REPLAY_VALID",
  "ANTI_SPLICING_VALID",
  "CLONE_OR_FORK_REJECTED",
  "PROOF_SIGNATURE_VALID",
];

function builderWithFullAxis(): ResultBuilder {
  const request: VerifierRequest = {
    verification_target_requested: "independent",
    input_mode: "artifact_set",
  };
  const b = new ResultBuilder(request);
  // The resolved target comes from which ARTIFACTS were supplied, not from the checks,
  // and a bare builder has none — without this it resolves to Issued and the axis is
  // correctly false for a different reason than the one under test.
  b.setResolvedTarget("Independent");
  for (const id of AXIS) b.pass(id);
  return b;
}

test("independent_valid: true when the whole axis passes", () => {
  const r = builderWithFullAxis().build();
  assert.equal(r.result_code, "INDEPENDENT_VALID");
  assert.equal(r.independent_valid, true);
});

test("independent_valid: survives a failed material comparison", () => {
  const b = builderWithFullAxis();
  // Exactly the partial-material case: the comparison ran and could not be finished.
  b.fail("ORIGINAL_MATERIAL_COMPARISON_VALID", "INCOMPLETE", "material missing for subject 1");
  const r = b.build();

  assert.equal(r.result_code, "INCOMPLETE", "result_code must still report the unfinished work");
  assert.equal(
    r.independent_valid,
    true,
    "the independence axis does not depend on original material"
  );
  // The neighboring axes hold too: this axis disagreeing with them is exactly how
  // the defect this test guards against would show.
  assert.equal(r.issued_valid, true);
  assert.equal(r.domain_valid, true);
  assert.equal(r.rules_domain_valid, true);
  assert.equal(r.proof_complete, true);
});

test("certcrypt_lineage: independence projection agrees with the axis", () => {
  // `independence_under_certcrypt_rules` is a PROJECTION of the same axis, not a copy
  // of `result_code`: otherwise a partial-material run would report the axis true and
  // the lineage false, the result contradicting itself on one question.
  const b = builderWithFullAxis();
  b.fail("ORIGINAL_MATERIAL_COMPARISON_VALID", "INCOMPLETE", "material missing for subject 1");
  const r = b.build();
  assert.equal(r.independent_valid, true);
  assert.equal(
    r.certcrypt_lineage?.independence_under_certcrypt_rules,
    true,
    "the lineage projection must not disagree with the axis it projects"
  );
  assert.equal(
    r.certcrypt_lineage?.history_bound_under_certcrypt,
    true,
    "history_bound folds the independence projection in, so it followed the same bug"
  );
});

test("certcrypt_lineage: a real axis failure still clears the projection", () => {
  const b = builderWithFullAxis();
  b.fail("SETTLEMENT_REF_VALID", "INDEPENDENT_INVALID", "settlement ref does not match");
  const r = b.build();
  assert.equal(r.certcrypt_lineage?.independence_under_certcrypt_rules, false);
  assert.equal(r.certcrypt_lineage?.history_bound_under_certcrypt, false);
});

test("independent_valid: false when a check ON the axis fails", () => {
  const b = builderWithFullAxis();
  b.fail("SETTLEMENT_REF_VALID", "INDEPENDENT_INVALID", "settlement ref does not match");
  const r = b.build();
  assert.equal(
    r.independent_valid,
    false,
    "a real axis failure must still report false — this is the half that matters"
  );
});

test("independent_valid: false when an axis check never ran", () => {
  const request: VerifierRequest = {
    verification_target_requested: "independent",
    input_mode: "artifact_set",
  };
  const b = new ResultBuilder(request);
  b.setResolvedTarget("Independent");
  // All but one: a check that was never executed must not read as a pass.
  for (const id of AXIS.filter((x) => x !== "NON_REPLAY_VALID")) b.pass(id);
  const r = b.build();
  assert.equal(r.independent_valid, false, "not executed is not passed");
});

test("independent_valid: false on an Issued-only target", () => {
  const request: VerifierRequest = {
    verification_target_requested: "issued",
    input_mode: "artifact_set",
  };
  const b = new ResultBuilder(request);
  for (const id of [
    "INPUT_TARGET_SUPPORTED",
    "INPUT_MODE_SUPPORTED",
    "INPUT_COMBINATION_VALID",
    "BASE_CERTIFICATE_PRESENT",
    "BASE_CERTIFICATE_STRUCTURE_VALID",
    "BASE_CERTIFICATE_AUTHENTIC",
  ] as CheckId[]) {
    b.pass(id);
  }
  const r = b.build();
  assert.equal(r.result_code, "ISSUED_VALID");
  assert.equal(
    r.independent_valid,
    false,
    "the independence plane was never evaluated, so it cannot be claimed"
  );
});
