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
 * Successor-binding observations on `verifyFoundation` (system-manifest/1 §9,
 * §12.3, §12.5).
 *
 * The conformance vectors P009 and QN4-QN8 pin the quorum counting. These cases
 * pin what the vectors do not: an observation is bound to the predecessor the
 * verifier actually holds, the §9 payload is a closed schema, and equivocation is
 * compared over canonical bytes rather than over whatever member order the
 * input happened to use.
 *
 * Driven by the published P009 and QN4 foundations from a sibling
 * `certcrypt-conformance` checkout; absent it, these tests skip.
 */
import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyFoundation } from "./verify-foundation.js";
import { ResultBuilder } from "../result/builder.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { SystemFoundation } from "../types/foundation.js";
import type { VerifierRequest } from "../types/request.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures");
const P009 = join(FIXTURES, "conformance", "P009", "artifacts", "system-foundation.json");
const QN4 = join(FIXTURES, "adversarial", "QN4", "artifacts", "system-foundation.json");

const skip = existsSync(P009) && existsSync(QN4)
  ? false
  : `conformance fixtures not found: check out certcrypt-conformance as a sibling of this repository (looked for ${P009})`;

const REQ: VerifierRequest = {
  verification_target_requested: "independent",
  input_mode: "artifact_set",
};

const STRICT = getConformanceConfig();

const load = (path: string): SystemFoundation =>
  JSON.parse(readFileSync(path, "utf-8")) as SystemFoundation;

/**
 * Run the foundation phase alone. `build()` also reports the phases this test
 * does not run as unexecuted, so only the foundation's own ids are kept.
 */
function run(foundation: SystemFoundation): { ok: boolean; failed: string[] } {
  const builder = new ResultBuilder(REQ);
  const fp = verifyFoundation(foundation, STRICT, builder);
  const failed = builder
    .build()
    .failed_check_ids.filter((id) => id.startsWith("FOUNDATION_"));
  return { ok: fp !== null, failed };
}

/** Reverse the member order of an object, recursively — JCS must not care. */
function reorder(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(reorder);
  if (v && typeof v === "object") {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>).reverse().map(([k, x]) => [k, reorder(x)])
    );
  }
  return v;
}

describe("successor-binding observations", { skip }, () => {
  // Verification checks the ML-DSA-65 component, which loads asynchronously.
  before(async () => {
    assert.ok(await initMlDsa65(), "ML-DSA-65 backend must be available");
  });

  it("accepts the published valid rotation", () => {
    assert.deepEqual(run(load(P009)), { ok: true, failed: [] });
  });

  it("accepts the same authenticated observation twice: repetition is not equivocation", () => {
    const f = load(P009);
    const obs = f.successor_binding_observations!;
    f.successor_binding_observations = [obs[0], structuredClone(obs[0])];
    assert.deepEqual(run(f), { ok: true, failed: [] });
  });

  it("rejects an observation naming a predecessor state the verifier does not hold", () => {
    // Changing the fingerprint also breaks the signatures; the point is that the
    // binding is refused for naming another manifest version, whatever its quorum.
    const f = load(P009);
    f.successor_binding_observations![0].successor_binding.predecessor_manifest_fingerprint =
      "00".repeat(32);
    const r = run(f);
    assert.equal(r.ok, false);
    assert.deepEqual(r.failed, ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]);
  });

  it("rejects a successor binding with a member outside the §9 payload", () => {
    const f = load(P009);
    (f.successor_binding_observations![0].successor_binding as unknown as Record<string, unknown>)
      .note = "extra";
    assert.deepEqual(run(f).failed, ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]);
  });

  it("rejects an empty observation list rather than reading it as no observations", () => {
    const f = load(P009);
    f.successor_binding_observations = [];
    assert.deepEqual(run(f).failed, ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]);
  });

  it("verifies the quorum over JCS bytes, so member order does not matter", () => {
    const f = load(P009);
    f.successor_binding_observations = reorder(f.successor_binding_observations) as never;
    assert.deepEqual(run(f), { ok: true, failed: [] });
  });

  it("detects equivocation regardless of member order inside the observations", () => {
    const f = load(QN4);
    const [a, b] = f.successor_binding_observations!;
    f.successor_binding_observations = [a, reorder(b) as typeof b];
    assert.deepEqual(run(f).failed, ["FOUNDATION_EQUIVOCATION_DETECTED"]);
  });

  it("does not let an unauthenticated observation establish equivocation", () => {
    // Strip the quorum from the second QN4 observation: it is no longer evidence,
    // and the input is rejected for the quorum, not as equivocation.
    const f = load(QN4);
    f.successor_binding_observations![1].predecessor_signatures = [];
    assert.deepEqual(run(f).failed, ["FOUNDATION_SUCCESSOR_QUORUM_VALID"]);
  });
});
