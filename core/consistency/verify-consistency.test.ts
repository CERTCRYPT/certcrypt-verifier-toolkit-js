/**
 * CCVP/1 behaviour the vectors pin only through outcomes: the instant reading
 * of timestamps, and the detail a result reports beside its outcome.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { ccvpInstant, verifyConsistency } from "./verify-consistency.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import { getConformanceConfig } from "../../harness/profiles.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(
  here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives",
  "ccvp-consistency", "vectors.json",
);

test("timestamps are instants: equal spellings of one instant compare equal", () => {
  assert.equal(ccvpInstant("2026-03-01T00:00:00Z"), ccvpInstant("2026-03-01T00:00:00.000Z"));
  assert.equal(ccvpInstant("2026-03-01T00:00:00.5Z"), ccvpInstant("2026-03-01T00:00:00.500000000Z"));
  // As strings these sort the other way round.
  assert.ok("2026-03-01T00:00:00.000Z" < "2026-03-01T00:00:00Z");
  assert.ok((ccvpInstant("2026-03-01T00:00:00.000000001Z") as bigint) > (ccvpInstant("2026-03-01T00:00:00Z") as bigint));
  assert.equal(ccvpInstant("1970-01-01T00:00:00Z"), 0n);
  assert.equal(ccvpInstant("0001-01-01T00:00:00Z"), -62135596800n * 1_000_000_000n);
});

test("timestamps outside the CCSP/1 UTC form are not instants", () => {
  for (const bad of [
    "2026-03-01T00:00:00+00:00", "2026-03-01t00:00:00z", "2026-03-01T00:00:60Z",
    "2026-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-03-01T24:00:00Z",
    "2026-03-01T00:00:00.Z", "2026-03-01T00:00:00.1234567890Z", "2026-03-01", 20260301, null,
  ]) {
    assert.equal(ccvpInstant(bad), null, String(bad));
  }
  assert.notEqual(ccvpInstant("2024-02-29T00:00:00Z"), null);
});

test("a match reports the namespace, the governing snapshot and the entry", async () => {
  if (!existsSync(VECTORS)) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const v = JSON.parse(readFileSync(VECTORS, "utf-8"));
  const cert = (n: string) => v.certificates[n].certificate;
  const r = verifyConsistency(cert("T_apr"), [cert("S_jan"), cert("S_tampered")], getConformanceConfig());
  assert.equal(r.outcome, "consistency-match");
  assert.equal(r.target_issued_valid, true);
  assert.deepEqual(r.namespace, v.namespace);
  assert.deepEqual(r.selected_snapshot, { snapshot_id: "01JAN0000000000000000000AA", issued_at: "2026-01-01T00:00:00Z" });
  assert.equal(r.matched_entry_index, 0);
  assert.equal(r.discarded_candidates, 1);
});

test("a target that is not Issued-valid yields unknown and says so", async () => {
  if (!existsSync(VECTORS)) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const v = JSON.parse(readFileSync(VECTORS, "utf-8"));
  const r = verifyConsistency(v.certificates.T_tampered.certificate, [v.certificates.S_jan.certificate], getConformanceConfig());
  assert.equal(r.outcome, "consistency-unknown");
  assert.equal(r.target_issued_valid, false);
  assert.equal(r.selected_snapshot, null);
});
