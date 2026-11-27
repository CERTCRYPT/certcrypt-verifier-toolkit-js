/**
 * The CCVP/1 consistency implementation checked against the certcrypt-conformance
 * primitive vectors (`fixtures/primitives/ccvp-consistency`).
 *
 * Every target and snapshot in those vectors is a signed certificate of the
 * conformance domain, so this runs the public operation exactly as an integrator
 * would: certificates in, outcome out. The vectors are the language-independent
 * contract — a third party reproduces every outcome from the public rules alone —
 * and running them here keeps the two from drifting.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyConsistency } from "./verify-consistency.js";
import { verify } from "../verify.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import { strictJsonParse } from "../input/strict-json.js";
import { getConformanceConfig } from "../../harness/profiles.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(
  here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives",
  "ccvp-consistency", "vectors.json",
);

interface Vectors {
  certificates: Record<string, { certificate: unknown; issued_valid: boolean; note: string }>;
  cases: { name: string; target: string; snapshots: string[]; expected_outcome: string; why: string }[];
}

function load(): Vectors | null {
  if (!existsSync(VECTORS)) {
    console.error("conformance ccvp-consistency vectors not found alongside toolkit; skipping");
    return null;
  }
  return strictJsonParse(readFileSync(VECTORS, "utf-8")) as Vectors;
}

test("CCVP/1 vectors: each certificate's Issued validity is what the vector states", async () => {
  const v = load();
  if (!v) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const config = getConformanceConfig();
  for (const [name, c] of Object.entries(v.certificates)) {
    const r = verify(
      { verification_target_requested: "issued", input_mode: "artifact_set", base_certificate: c.certificate as never },
      config,
    );
    assert.equal(r.result_code === "ISSUED_VALID", c.issued_valid, `${name}: ${r.failure_reason}`);
  }
});

test("CCVP/1 vectors: every resolution case reproduces its expected outcome", async () => {
  const v = load();
  if (!v) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const config = getConformanceConfig();
  const seen = new Set<string>();
  for (const c of v.cases) {
    const r = verifyConsistency(
      v.certificates[c.target].certificate,
      c.snapshots.map((n) => v.certificates[n].certificate),
      config,
    );
    assert.equal(r.outcome, c.expected_outcome, `${c.name}: ${c.why} — got: ${r.reason}`);
    seen.add(c.expected_outcome);
  }
  // A suite that only ever expected one outcome would pass a constant function.
  assert.deepEqual([...seen].sort(), ["consistency-match", "consistency-mismatch", "consistency-unknown"]);
});
