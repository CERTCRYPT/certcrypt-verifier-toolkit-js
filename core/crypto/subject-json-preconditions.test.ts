/**
 * Fail-closed precondition tests for the JSON-object subject profiles. Each spec
 * states that field-set / value-discipline conformance is a *precondition of
 * canonicalization*: a non-conformant object means the profile does not apply and
 * the implementation MUST fail closed (subject.collection/1,
 * subject.ai-decision/1, subject.context-snapshot/1).
 *
 * These tests assert that (a) a conformant object passes, and (b) each specific
 * violation throws SubjectPreconditionError — so canonicalization is never
 * reached for a non-conformant subject.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  SubjectPreconditionError,
  assertCollectionPrecondition,
  assertAiDecisionPrecondition,
  assertContextSnapshotPrecondition,
} from "./subject-json-preconditions.js";
import {
  canonicalBytesForSubject,
  SUBJECT_COLLECTION,
  SUBJECT_AI_DECISION,
} from "./canonical-subject.js";

const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const throwsPrecond = (fn: () => unknown) =>
  assert.throws(fn, (e: unknown) => e instanceof SubjectPreconditionError);

// ---- subject.collection/1 ----

const goodCollection = {
  commitment_scheme: "collection.merkle-sha3-256/1",
  root: "a".repeat(64),
  declared_cardinality: "3",
  // Heterogeneous on purpose: each leaf declares its own profile (§7.4).
  leaves: [
    { profile: "subject.text/1", commitment_digest_hex: "b".repeat(64) },
    { profile: "subject.binary/1", commitment_digest_hex: "c".repeat(64) },
    { profile: "subject.text/1", commitment_digest_hex: "d".repeat(64) },
  ],
};

test("collection: conformant object passes", () => {
  assert.doesNotThrow(() => assertCollectionPrecondition(goodCollection));
});

test("collection: extra member is rejected (exactly four)", () => {
  throwsPrecond(() => assertCollectionPrecondition({ ...goodCollection, extra: "x" }));
});

test("collection: a `type` member is an extra member", () => {
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, type: "subject.collection/1" }),
  );
});

test("collection: missing member is rejected", () => {
  const { root, ...missing } = goodCollection;
  throwsPrecond(() => assertCollectionPrecondition(missing));
});

test("collection: empty leaves[] is rejected", () => {
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, declared_cardinality: "0", leaves: [] }),
  );
});

test("collection: a leaf missing its profile is rejected", () => {
  throwsPrecond(() =>
    assertCollectionPrecondition({
      ...goodCollection,
      leaves: [{ commitment_digest_hex: "b".repeat(64) }, ...goodCollection.leaves.slice(1)],
    }),
  );
});

test("collection: a non-hex leaf commitment is rejected", () => {
  throwsPrecond(() =>
    assertCollectionPrecondition({
      ...goodCollection,
      leaves: [
        { profile: "subject.text/1", commitment_digest_hex: "nothex" },
        ...goodCollection.leaves.slice(1),
      ],
    }),
  );
});

test("collection: declared_cardinality disagreeing with leaves[] is rejected", () => {
  // The economic layer reads declared_cardinality (§7.4.3), so a disagreement
  // must be a hard failure rather than something derived away.
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, declared_cardinality: "2" }),
  );
});

test("collection: non-string member is rejected (all strings)", () => {
  throwsPrecond(() => assertCollectionPrecondition({ ...goodCollection, declared_cardinality: 3 }));
});

test("collection: declared_cardinality grammar — leading zero, sign, zero, non-numeric", () => {
  for (const dc of ["03", "+3", "-3", "0", "", "3.0", "0x3", "3 "]) {
    throwsPrecond(() => assertCollectionPrecondition({ ...goodCollection, declared_cardinality: dc }));
  }
});

test("collection: declared_cardinality > 2^64−1 is rejected", () => {
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, declared_cardinality: "18446744073709551616" }),
  );
});

test("collection: cardinality above 2^64−1 is rejected on grammar, not on leaf count", () => {
  // 2^64−1 is not reachable in a conformant object: §7.4 requires
  // declared_cardinality to equal leaves.length, so declaring it means shipping that
  // many leaves. The bound is kept as a guard on the grammar, and what a caller
  // actually hits first is the disagreement with leaves[].
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, declared_cardinality: "18446744073709551616" }),
  );
  throwsPrecond(() =>
    assertCollectionPrecondition({ ...goodCollection, declared_cardinality: "18446744073709551615" }),
  );
});

test("collection: bad root shape under merkle-sha3-256 is rejected", () => {
  throwsPrecond(() => assertCollectionPrecondition({ ...goodCollection, root: "A".repeat(64) })); // uppercase
  throwsPrecond(() => assertCollectionPrecondition({ ...goodCollection, root: "a".repeat(63) })); // short
});

test("collection: dispatcher fails closed for a non-conformant object", () => {
  throwsPrecond(() => canonicalBytesForSubject(SUBJECT_COLLECTION, enc({ ...goodCollection, extra: "x" })));
});

// ---- subject.ai-decision/1 ----

const goodAi = {
  profile: "subject.ai-decision/1",
  decision_id: "decision-4471",
  decided_at: "2026-04-12T10:00:00.000Z",
  model: { id: "example-model", provider: "example-provider", version: "example-model-1" },
  observation_scope: "client",
  input: [{ id: "prompt", role: "prompt", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: "1".repeat(64), commitment_digest_hex: "a".repeat(64) }],
  output: [{ id: "answer", role: "response", media_type: "text/plain", profile: "subject.text/1", material_nonce_hex: "2".repeat(64), commitment_digest_hex: "b".repeat(64) }],
  decision: "approved",
};

test("ai-decision: conformant record passes (required members only)", () => {
  assert.doesNotThrow(() => assertAiDecisionPrecondition(goodAi));
});

test("ai-decision: conformant record with optional string-only parameters passes", () => {
  assert.doesNotThrow(() =>
    assertAiDecisionPrecondition({
      ...goodAi,
      parameters: { temperature: "0.0", max_tokens: "512" },
      context: { channel: "interactive" },
      started_at: "2026-04-12T09:59:59.000Z",
      actor_id: "op-1",
      policy_ref: "policy-7",
    }),
  );
});

test("ai-decision: a JSON number anywhere is rejected (fail-closed)", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, parameters: { temperature: 0.0 } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, model: { id: "m", provider: "p", extra_num: 1 as unknown as string } }));
});

test("ai-decision: a JSON boolean or null is rejected", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, decision: true as unknown as string }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, policy_ref: null as unknown as string }));
});

test("ai-decision: missing required member is rejected", () => {
  const { decision, ...missing } = goodAi;
  throwsPrecond(() => assertAiDecisionPrecondition(missing));
});

test("ai-decision: unexpected top-level member is rejected", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, surprise: "x" }));
});

test("ai-decision: wrong nested object shape is rejected", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, model: { id: "m" } })); // missing provider
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [{}] }));
});

test("ai-decision: model.version optional string is accepted", () => {
  assert.doesNotThrow(() =>
    assertAiDecisionPrecondition({ ...goodAi, model: { id: "m", provider: "p", version: "1" } }),
  );
});

test("ai-decision: decision and every declared model member are non-empty", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, decision: "" }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, model: { id: "", provider: "p" } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, model: { id: "m", provider: "" } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, model: { id: "m", provider: "p", version: "" } }));
});

test("ai-decision: parameters members must be flat strings (§7.2)", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, parameters: { stop: ["a"] } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, parameters: { nested: { x: "1" } } }));
  assert.doesNotThrow(() => assertAiDecisionPrecondition({ ...goodAi, parameters: {} }));
});

test("ai-decision: context is a flat string map and both maps are bounded", () => {
  assert.doesNotThrow(() => assertAiDecisionPrecondition({ ...goodAi, context: { channel: "runtime" } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, context: { nested: { x: "1" } } }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, parameters: Object.fromEntries(Array.from({ length: 129 }, (_, i) => [`p${i}`, "x"])) }));
});

test("ai-decision: material nonce and commitment must be 64 lowercase hex characters (§7.3)", () => {
  for (const bad of ["aa", "A".repeat(64), "g".repeat(64), "a".repeat(65)]) {
    throwsPrecond(() =>
      assertAiDecisionPrecondition({ ...goodAi, output: [{ ...goodAi.output[0], material_nonce_hex: bad }] }),
    );
    throwsPrecond(() =>
      assertAiDecisionPrecondition({ ...goodAi, output: [{ ...goodAi.output[0], commitment_digest_hex: bad }] }),
    );
  }
});

test("ai-decision: material nonces are unique and legacy raw digests are rejected", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({
    ...goodAi,
    output: [{ ...goodAi.output[0], material_nonce_hex: goodAi.input[0].material_nonce_hex }],
  }));
  throwsPrecond(() => assertAiDecisionPrecondition({
    ...goodAi,
    input: [{ ...goodAi.input[0], digest_hex: "a".repeat(64) }],
  }));
  throwsPrecond(() => assertAiDecisionPrecondition({
    ...goodAi,
    input: [{ ...goodAi.input[0], subject_local_digest_hex: "a".repeat(64) }],
  }));
});

test("ai-decision: input/output profile must be one of §7.4", () => {
  for (const profile of ["subject.collection/1", "subject.context-snapshot/1", "subject.unknown/1", ""]) {
    throwsPrecond(() =>
      assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], profile }] }),
    );
  }
  for (const profile of ["subject.text/1", "subject.binary/1", "subject.email/1", "subject.ai-decision/1"]) {
    assert.doesNotThrow(() =>
      assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], profile }] }),
    );
  }
});

test("ai-decision: timestamps are valid Gregorian UTC milliseconds", () => {
  for (const ok of ["2026-04-12T10:00:00.000Z", "2024-02-29T23:59:59.999Z"]) {
    assert.doesNotThrow(() => assertAiDecisionPrecondition({ ...goodAi, decided_at: ok }), ok);
  }
  for (const bad of ["2026-02-29T10:00:00.000Z", "2026-04-31T10:00:00.000Z", "2026-04-12T10:00:00Z", "2026-04-12T10:00:00.1Z", "2026-04-12T10:00:00.0000Z", "2026-04-12T10:00:00.000+02:00", "0000-01-01T00:00:00.000Z"]) {
    throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, decided_at: bad }));
  }
  assert.doesNotThrow(() => assertAiDecisionPrecondition({ ...goodAi, started_at: goodAi.decided_at }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, started_at: "2026-04-12T10:00:00.001Z" }));
});

test("ai-decision: part shape, ids, media types and total cardinality fail closed", () => {
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [] , output: [] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, output: [] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, output: [{ ...goodAi.output[0], id: "prompt" }] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], id: "Bad" }] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], role: "" }] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], media_type: "Text/Plain" }] }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: [{ ...goodAi.input[0], media_type: "text/plain; charset=utf-8" }] }));
  const many = Array.from({ length: 257 }, (_, i) => ({ ...goodAi.input[0], id: `p${i}` }));
  throwsPrecond(() => assertAiDecisionPrecondition({ ...goodAi, input: many, output: [] }));
});

test("ai-decision: dispatcher fails closed for a record with a JSON number", () => {
  throwsPrecond(() => canonicalBytesForSubject(SUBJECT_AI_DECISION, enc({ ...goodAi, parameters: { t: 1 } })));
});

test("ai-decision: source material larger than 1 MiB is rejected before parsing", () => {
  const oversized = new Uint8Array(1024 * 1024 + 1);
  assert.throws(() => canonicalBytesForSubject(SUBJECT_AI_DECISION, oversized), /source material exceeds/);
});

test("ai-decision: a UTF-8 BOM is rejected, never stripped", () => {
  const json = new TextEncoder().encode(JSON.stringify(goodAi));
  const bom = Uint8Array.from([0xef, 0xbb, 0xbf, ...json]);
  assert.throws(() => canonicalBytesForSubject(SUBJECT_AI_DECISION, bom));
});

// ---- subject.context-snapshot/1 ----

test("context-snapshot: string-only object passes", () => {
  assert.doesNotThrow(() =>
    assertContextSnapshotPrecondition({ a: "1", nested: { b: "2" }, list: ["x", "y"] }),
  );
});

test("context-snapshot: a JSON number anywhere is rejected", () => {
  throwsPrecond(() => assertContextSnapshotPrecondition({ a: "1", n: 2 }));
  throwsPrecond(() => assertContextSnapshotPrecondition({ a: "1", nested: { deep: [ "ok", 3 ] } }));
});

test("context-snapshot: booleans and nulls are PERMITTED, numbers are not", () => {
  // Narrower than the string-only discipline of collection/ai-decision, and
  // deliberately so. subject.context-snapshot/1 §7 requires preserving "the exact
  // string, boolean, array, object, and null semantics of the input" and §8
  // forbids coercing "booleans or nulls into strings". CCVP/1 §7.1 depends on it:
  // its normative entry example carries `valid_to: null` for an open-ended
  // eligibility window, and §8 reads `entry.valid_to is not null`.
  //
  // Only numbers are excluded, because number serialization is the sole RFC 8785
  // divergence vector across languages (§7.1). Booleans and nulls canonicalize
  // identically everywhere, so excluding them bought nothing and made the
  // governing protocol's own example non-conformant.
  assert.doesNotThrow(() => assertContextSnapshotPrecondition({ a: true }));
  assert.doesNotThrow(() => assertContextSnapshotPrecondition({ a: null }));
  throwsPrecond(() => assertContextSnapshotPrecondition({ a: 1 }));
  throwsPrecond(() => assertContextSnapshotPrecondition({ a: [{ b: 2 }] }));
});
