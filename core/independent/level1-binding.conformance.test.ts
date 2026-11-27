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
 * Level-1 binding signing bytes, against the contract.
 *
 * This toolkit RECONSTRUCTS these bytes to check the system domain's signature
 * over a holder authorization. Reconstructing them differently means rejecting
 * bindings the system domain actually signed — a false REJECT, which is the
 * failure mode a verifier can least afford.
 *
 * The bytes are insertion-ordered, not JCS. Both canonicalizations coexist in
 * this system (the evidence digest DOES use JCS), so reaching for the wrong one
 * is the natural mistake rather than an exotic one. The contract pins the digest
 * JCS would have produced, and this test reproduces that too: a tripwire only
 * works while it still describes what the mistake actually yields.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";

import { level1BindingSigningBytes } from "../types/capacity-evidence.js";
import { digestHexBytes } from "../crypto/digest.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";

const HERE = dirname(fileURLToPath(import.meta.url));

function vectors(): any | null {
  const base =
    process.env.CERTCRYPT_CONFORMANCE_DIR ??
    join(HERE, "..", "..", "..", "..", "certcrypt-conformance", "fixtures");
  const path = join(base, "primitives", "level1-binding", "vectors.json");
  return existsSync(path) ? JSON.parse(readFileSync(path, "utf-8")) : null;
}

test("Level-1 binding signing bytes match the contract", () => {
  const v = vectors();
  if (v === null) return; // absence is the conformance runner's failure to report

  for (const vec of v.vectors) {
    const bytes = level1BindingSigningBytes(vec.binding);
    assert.equal(
      new TextDecoder().decode(bytes),
      vec.expected_signing_bytes_utf8,
      `level1-binding '${vec.label}': signing bytes diverged — field order or encoding`
    );
    assert.equal(
      digestHexBytes(bytes),
      vec.expected_signing_bytes_digest,
      `level1-binding '${vec.label}': signing-bytes digest diverged`
    );
  }
});

test("the JCS tripwire still describes what JCS yields", () => {
  // If this fails, the vector's warning has gone stale: it would no longer catch
  // the mistake it names, and an implementation reaching for JCS would drift
  // past a tripwire that no longer trips.
  const v = vectors();
  if (v === null) return;

  for (const vec of v.vectors) {
    const jcs = jcsCanonicalizeBytes(vec.binding);
    assert.equal(
      digestHexBytes(jcs),
      vec.expected_digest_if_jcs_wrongly_applied,
      `level1-binding '${vec.label}': the JCS tripwire no longer describes what JCS produces`
    );
  }
});
