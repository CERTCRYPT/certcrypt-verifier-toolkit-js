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
 * Which primitive families this toolkit accounts for, and why.
 *
 * The parity tests answer "do the bytes match?". This file answers the question
 * that comes before it: "is anyone checking this family at all?". A contract can
 * gain families that no consumer reads, and nothing fails; only a check like
 * this makes that loud.
 *
 * The verdict fixtures are a different matter: a verifier is held to ALL of them,
 * and `scripts/run-conformance.ts` already enforces that. This file is only about
 * the primitive byte-contract vectors, which divide by role.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";
import test from "node:test";

const HERE = dirname(new URL(import.meta.url).pathname);
// dist/core/conformance -> dist/core -> dist -> toolkit root
const TOOLKIT_ROOT = join(HERE, "..", "..", "..");

/**
 * Families a VERIFIER is held to: every construction whose bytes it
 * reconstructs in order to check a signature or resolve a value.
 *
 * Each entry names the test that reads it, so a claim here points at something
 * that can be run rather than at a promise.
 */
const ACCOUNTED_FOR: ReadonlyArray<readonly [string, string]> = [
  ["collection-merkle", "core/crypto/collection-inclusion.test.ts"],
  ["subject-text", "core/crypto/canonical-subject.test.ts"],
  ["subject-email", "core/crypto/canonical-subject.test.ts"],
  ["subject-binary", "core/crypto/canonical-subject.test.ts"],
  ["subject-collection", "core/crypto/canonical-subject.test.ts"],
  ["subject-ai-decision", "core/crypto/canonical-subject.test.ts"],
  ["subject-context-snapshot", "core/crypto/canonical-subject.test.ts"],
  ["original-material", "core/issued/verify-original-material.test.ts"],
  ["pseudonym", "core/independent/capacity-evidence.test.ts"],
  ["holder-keyset", "core/independent/capacity-evidence.test.ts"],
  ["capacity-evidence", "core/independent/capacity-evidence.test.ts"],
  ["independence-proof-signature", "core/independent/verify-proof-signature.test.ts"],
  ["ccvp-consistency", "core/consistency/vectors.test.ts"],
  ["composite-m-prime", "core/crypto/composite.conformance.test.ts"],
  ["composite-verification", "core/crypto/composite.conformance.test.ts"],
  ["level1-binding", "core/independent/level1-binding.conformance.test.ts"],
  ["strict-json", "core/input/strict-json.test.ts"],
] as const;

/**
 * Families that exist in the contract and do not bind a verifier, each with the
 * reason. Producer-side constructions: a verifier never performs them, so holding
 * it to them would make conformance unachievable rather than stricter.
 *
 * `operator-receipt` is the uncomfortable one: a verifier that checked a
 * receipt would reconstruct those bytes, so it would belong in the list above.
 * This toolkit checks none, and the family is named here rather than quietly
 * absent — an acknowledged exclusion is a decision; an unlisted one is a
 * surprise.
 */
const OUT_OF_SCOPE: ReadonlyArray<readonly [string, string]> = [
  ["artifact-shape", "field sets bind whoever emits a preimage; pinned producer-side"],
  ["key-derivation", "producer-side; not performed by a verifier"],
  ["manifest-resolution", "this toolkit resolves through the caller's supplied manifest"],
  ["rules-domain", "the domain table is consumed through the proof, not resolved here"],
  ["settlement-preimages", "assembled producer-side; the verifier checks the resulting digests"],
  ["submission-set", "the id is recomputed producer-side"],
  ["submission-set-limits", "producer-side; not performed by a verifier"],
  ["verification-package", "assembling the golden package is producer-side; a verifier reads packages through the package-mode verdict fixtures"],
  ["issuer-key-derivation", "producer-side; not performed by a verifier"],
  ["ecdsa-p256-deterministic", "producer-side; not performed by a verifier, which accepts any valid low-s ECDSA P-256 signature"],
  ["operator-receipt", "transport-side: the receipt is detachable and opt-in, no verdict fixture depends on one, and a verifier without a receipt reaches the same result. This toolkit handles no receipts, so there is nothing here to hold to the vector"],
  ["operator-domain-binding", "this toolkit does not verify domain-binding statements; they are not part of any proof"],
] as const;

/** The contract's `fixtures/primitives`, or null when it is not checked out. */
function primitivesDir(): string | null {
  const envDir = process.env.CERTCRYPT_CONFORMANCE_DIR;
  const base =
    envDir && existsSync(envDir)
      ? envDir
      : join(TOOLKIT_ROOT, "..", "certcrypt-conformance", "fixtures");
  const dir = join(base, "primitives");
  return existsSync(dir) ? dir : null;
}

test("every claimed family exists in the contract", () => {
  const dir = primitivesDir();
  if (dir === null) return; // absence is the conformance runner's failure to report
  for (const [family, testFile] of ACCOUNTED_FOR) {
    assert.ok(
      existsSync(join(dir, family)),
      `this toolkit claims to cover '${family}' (via ${testFile}), which the contract ` +
        `does not have — renamed or removed upstream, so the claim is now false`
    );
  }
});

test("every excused family exists in the contract", () => {
  const dir = primitivesDir();
  if (dir === null) return;
  for (const [family] of OUT_OF_SCOPE) {
    assert.ok(
      existsSync(join(dir, family)),
      `'${family}' is excused as out of scope, but the contract does not have it — ` +
        `renamed or removed upstream, so drop the entry rather than excuse nothing`
    );
  }
});

test("every claimed test file exists", () => {
  for (const [family, testFile] of ACCOUNTED_FOR) {
    // Sources live beside dist/; check the TypeScript, which is what a reader opens.
    const path = join(TOOLKIT_ROOT, testFile);
    assert.ok(
      existsSync(path),
      `'${family}' claims to be covered by ${testFile}, which does not exist — ` +
        `the coverage claim names nothing`
    );
  }
});

test("a family the contract grows must be classified, not ignored", () => {
  const dir = primitivesDir();
  if (dir === null) return;
  const classified = new Set([
    ...ACCOUNTED_FOR.map(([f]) => f),
    ...OUT_OF_SCOPE.map(([f]) => f),
  ]);
  const unclassified = readdirSync(dir, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .map((e) => e.name)
    .filter((name) => !classified.has(name))
    .sort();
  assert.deepEqual(
    unclassified,
    [],
    `the contract carries families this toolkit has not classified: ${JSON.stringify(unclassified)}. ` +
      `Add each to ACCOUNTED_FOR with the test that reads it, or to OUT_OF_SCOPE with the reason ` +
      `it does not apply. A family nobody classifies is a family nobody checks.`
  );
});

test("no family is both accounted for and out of scope", () => {
  const excused = new Set(OUT_OF_SCOPE.map(([f]) => f));
  for (const [family] of ACCOUNTED_FOR) {
    assert.ok(
      !excused.has(family),
      `'${family}' is both accounted for and out of scope — one of the two is wrong`
    );
  }
});

test("no gap is left unrecorded", () => {
  // Turning a GAP into coverage means moving it to ACCOUNTED_FOR. This test fails
  // if someone deletes the entry instead — which would make the gap disappear from
  // the record without anything having been checked.
  //
  // The list is empty today: every family this toolkit performs is accounted for,
  // and the ones it does not perform carry the reason instead of a promise.
  const gaps = OUT_OF_SCOPE.filter(([, why]) => why.startsWith("GAP:")).map(([f]) => f);
  assert.deepEqual(
    gaps.sort(),
    [],
    "the recorded gaps changed: close one by moving it to ACCOUNTED_FOR with a test that " +
      "reads its vector, never by removing the entry"
  );
});
