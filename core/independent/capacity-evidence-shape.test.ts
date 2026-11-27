import { before, test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getConformanceConfig } from "../../harness/profiles.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { VerifierRequest } from "../types/request.js";
import { verify } from "../verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(
  here,
  "..",
  "..",
  "..",
  "..",
  "certcrypt-conformance",
  "fixtures",
  "conformance",
  "P001",
  "artifacts"
);
const fixtureSkip = existsSync(FIXTURE)
  ? false
  : `conformance fixture P001 not found at ${FIXTURE}`;

function fixtureRequest(): VerifierRequest {
  const load = (name: string) => JSON.parse(readFileSync(join(FIXTURE, name), "utf8"));
  return {
    verification_target_requested: "independent",
    input_mode: "artifact_set",
    base_certificate: load("base-certificate.json"),
    independence_proof: load("independence-proof.json"),
    settlement_material: load("settlement-material.json"),
    capacity_evidence: load("capacity-evidence.json"),
    commitment_inclusion_proof: load("commitment-inclusion-proof.json"),
    system_foundation: load("system-foundation.json"),
  };
}

before(async () => {
  assert.ok(await initMlDsa65(), "@noble/post-quantum required");
});

function expectCapacityRefusal(mutate: (evidence: any) => void): void {
  const request = fixtureRequest();
  const evidence = structuredClone(request.capacity_evidence) as any;
  mutate(evidence);
  request.capacity_evidence = evidence;
  let result: ReturnType<typeof verify> | undefined;
  assert.doesNotThrow(() => {
    result = verify(request, getConformanceConfig());
  });
  assert.equal(result?.result_code, "INDEPENDENT_INVALID");
  assert.deepEqual(result?.failed_check_ids, ["CAPACITY_EVIDENCE_VALID"]);
}

test("malformed capacity evidence returns a verdict instead of throwing", { skip: fixtureSkip }, () => {
  expectCapacityRefusal((evidence) => delete evidence.projected_commitment);
  expectCapacityRefusal((evidence) => {
    evidence.projected_authorization = [];
  });
  expectCapacityRefusal((evidence) => {
    evidence.operation_key.tree_size = "1";
  });
  expectCapacityRefusal((evidence) => {
    evidence.unexpected = true;
  });
  expectCapacityRefusal((evidence) => {
    evidence.projected_commitment.unexpected = true;
  });
});

test("operation_salt_hex is lowercase hexadecimal bytes", { skip: fixtureSkip }, () => {
  for (const salt of ["", "0", "zz", "AA"]) {
    expectCapacityRefusal((evidence) => {
      evidence.operation_salt_hex = salt;
    });
  }
});

test("commitment instants are real RFC 3339 UTC whole-second values", { skip: fixtureSkip }, () => {
  for (const instant of [
    "2026-02-30T00:00:00Z",
    "2026-01-01",
    "2026-01-01T00:00:00.000Z",
    "2026-01-01T01:00:00+01:00",
  ]) {
    expectCapacityRefusal((evidence) => {
      evidence.projected_commitment.issued_at = instant;
    });
  }
});
