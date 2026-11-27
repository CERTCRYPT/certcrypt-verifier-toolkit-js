/**
 * `subject_scope` coverage — the field that marks whether a verdict covers an
 * opaque input or declared elements. The rule (builder.ts setSubjectScope): a
 * `subject.collection/1` subject is `opaque: false` (its elements are declared and
 * element-level inclusion is available); EVERY other profile is `opaque: true` — a
 * single opaque input whose internal contents the proof does NOT cover. This closes
 * the "a container proves its children" over-read: a ZIP submitted as
 * `subject.binary/1` is one opaque subject, not many proven records.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { ResultBuilder } from "./builder.js";
import { SUBJECT_COLLECTION } from "../crypto/canonical-subject.js";
import type { VerifierRequest } from "../types/index.js";

function newBuilder(): ResultBuilder {
  const request: VerifierRequest = {
    verification_target_requested: "auto",
    input_mode: "package",
  };
  return new ResultBuilder(request);
}

test("subject_scope: null until the base certificate is parsed", () => {
  const b = newBuilder();
  const result = b.build();
  assert.equal(result.subject_scope, null, "no subjects recorded -> null, not []");
});

test("subject_scope: a collection subject is declared (opaque: false)", () => {
  const b = newBuilder();
  b.setSubjectScope([SUBJECT_COLLECTION]);
  const result = b.build();
  assert.deepEqual(result.subject_scope, [{ profile: SUBJECT_COLLECTION, opaque: false }]);
});

test("subject_scope: a binary subject is opaque (opaque: true)", () => {
  const b = newBuilder();
  b.setSubjectScope(["subject.binary/1"]);
  const result = b.build();
  assert.deepEqual(result.subject_scope, [{ profile: "subject.binary/1", opaque: true }]);
});

test("subject_scope: every non-collection profile is opaque", () => {
  const b = newBuilder();
  const profiles = ["subject.binary/1", "subject.text/1", "subject.email/1", "subject.ai-decision/1"];
  b.setSubjectScope(profiles);
  const result = b.build();
  assert.ok(result.subject_scope);
  for (const s of result.subject_scope!) {
    assert.equal(s.opaque, true, `${s.profile} must be opaque (only collections declare elements)`);
  }
});

test("subject_scope: preserves anchor order and distinguishes collection from opaque", () => {
  const b = newBuilder();
  // Mixed anchor: opaque container, then a declared collection, then another opaque.
  b.setSubjectScope(["subject.binary/1", SUBJECT_COLLECTION, "subject.text/1"]);
  const result = b.build();
  assert.deepEqual(result.subject_scope, [
    { profile: "subject.binary/1", opaque: true },
    { profile: SUBJECT_COLLECTION, opaque: false },
    { profile: "subject.text/1", opaque: true },
  ]);
  // The whole point of the field: a collection is distinguishable from an opaque
  // container in the SAME result, so a consumer cannot silently over-read.
  const collectionEntries = result.subject_scope!.filter((s) => !s.opaque);
  assert.equal(collectionEntries.length, 1);
  assert.equal(collectionEntries[0].profile, SUBJECT_COLLECTION);
});

test("subject_scope: empty anchor yields an empty (non-null) scope list", () => {
  const b = newBuilder();
  b.setSubjectScope([]);
  const result = b.build();
  assert.deepEqual(result.subject_scope, [], "an anchor parsed with zero subjects -> [], distinct from null");
});
