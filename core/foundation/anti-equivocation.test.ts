/**
 * Tests for anti-equivocation detection (system-manifest/1).
 *
 * Covers: first observation persists clean; identical re-observation is a no-op
 * (no duplicate, no false positive); a conflicting observation under the SAME
 * index tuple is detected for each conflict field; observations under DIFFERENT
 * index tuples never collide; both observations are retained as evidence on
 * detection; the injectable store contract works with a custom implementation.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  type SuccessorBindingObservation,
  type ObservationStore,
  InMemoryObservationStore,
  observationIndexKey,
  checkAndRecord,
} from "./anti-equivocation.js";

function obs(
  over: Partial<SuccessorBindingObservation> = {}
): SuccessorBindingObservation {
  return {
    system_id: "example-system",
    predecessor_manifest_fingerprint: "fp-pred",
    predecessor_manifest_sequence: 0,
    predecessor_kid: "kid-2026",
    successor_kid: "kid-2027",
    successor_algorithm: "certcrypt-composite-p256-mldsa65-v1",
    successor_public_key_p256_b64: "P256SUCC",
    successor_public_key_mldsa_b64: "MLDSASUCC",
    successor_valid_from: "2027-01-15T12:00:00Z",
    predecessor_signature: { alg: "x", mode: "AND", signatures: [] },
    ...over,
  };
}

test("first observation persists and is not equivocation", () => {
  const store = new InMemoryObservationStore();
  const v = checkAndRecord(store, obs());
  assert.equal(v.equivocation, false);
  assert.equal(store.getByIndex(observationIndexKey(obs())).length, 1);
});

test("identical re-observation is a no-op (idempotent, no duplicate)", () => {
  const store = new InMemoryObservationStore();
  checkAndRecord(store, obs());
  const v = checkAndRecord(store, obs());
  assert.equal(v.equivocation, false);
  assert.equal(
    store.getByIndex(observationIndexKey(obs())).length,
    1,
    "identical observation must not be persisted twice"
  );
});

// Each conflict field, in isolation, must trigger detection.
for (const field of [
  "successor_kid",
  "successor_algorithm",
  "successor_public_key_p256_b64",
  "successor_public_key_mldsa_b64",
  "successor_valid_from",
] as const) {
  test(`conflict on ${field} under same index tuple is detected`, () => {
    const store = new InMemoryObservationStore();
    checkAndRecord(store, obs());
    const v = checkAndRecord(store, obs({ [field]: "DIFFERENT-VALUE" }));
    assert.equal(v.equivocation, true, "must be flagged as equivocation");
    assert.ok(v.conflict, "must carry conflict evidence");
    assert.deepEqual(v.conflict!.fields, [field]);
    // BOTH observations retained as canonical evidence.
    assert.equal(
      store.getByIndex(observationIndexKey(obs())).length,
      2,
      "both conflicting observations must be retained"
    );
  });
}

test("different index tuple does not collide (no false positive)", () => {
  const store = new InMemoryObservationStore();
  checkAndRecord(store, obs());
  // Same conflict-surface change BUT a different predecessor entry => different
  // index tuple => a separate, legitimate binding, not equivocation.
  const v = checkAndRecord(
    store,
    obs({ predecessor_kid: "kid-OTHER", successor_kid: "kid-OTHER-SUCC" })
  );
  assert.equal(v.equivocation, false);
});

test("multiple conflict fields are all reported", () => {
  const store = new InMemoryObservationStore();
  checkAndRecord(store, obs());
  const v = checkAndRecord(
    store,
    obs({ successor_kid: "X", successor_public_key_mldsa_b64: "Y" })
  );
  assert.equal(v.equivocation, true);
  assert.deepEqual(
    [...v.conflict!.fields].sort(),
    ["successor_kid", "successor_public_key_mldsa_b64"].sort()
  );
});

test("works with an injected custom ObservationStore (plug-and-play contract)", () => {
  // A trivial durable-store stand-in proving the interface is enough to plug in
  // real persistence without touching detection logic.
  const backing = new Map<string, SuccessorBindingObservation[]>();
  const custom: ObservationStore = {
    getByIndex: (k) => backing.get(k) ?? [],
    put: (k, o) => {
      const l = backing.get(k);
      if (l) l.push(o);
      else backing.set(k, [o]);
    },
  };
  assert.equal(checkAndRecord(custom, obs()).equivocation, false);
  assert.equal(
    checkAndRecord(custom, obs({ successor_kid: "EVIL" })).equivocation,
    true
  );
});
