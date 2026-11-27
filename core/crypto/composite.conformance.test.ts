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
 * Composite signature parity against the conformance contract.
 *
 * Two halves. The framing (M′) is the last deterministic step before signing, and
 * where a divergence does the most damage: this toolkit and the reference producer
 * framing it differently means each verifies its OWN signatures perfectly and
 * neither verifies the other's — every local test green on both sides.
 *
 * The refusals are the half that needs saying out loud. A valid signature proves
 * the math works and says nothing about what the code does with an invalid one.
 * These refusals are policy this toolkit enforces, not properties the
 * cryptography provides — the post-quantum floor above all, whose absence leaves
 * a composite whose remaining half verifies perfectly.
 *
 * What is deliberately NOT attempted: showing that no forged signature ever
 * verifies. That belongs to the ECDSA and ML-DSA implementations, and no fixture
 * can establish it.
 */

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import {
  compositeMPrime,
  verifyComposite,
  PROFILE_P256_MLDSA65,
  PROFILE_ED25519_MLDSA65,
  type CompositeSignatureWire,
} from "./composite.js";
// CERTCRYPT_CONFORMANCE_DIR points at the conformance `fixtures/` dir (the same
// convention scripts/run-conformance.ts uses), NOT the repo root.
const HERE = dirname(fileURLToPath(import.meta.url));

/** The contract's `fixtures/primitives`, or null when it is not checked out. */
function primitivesDir(): string | null {
  const base =
    process.env.CERTCRYPT_CONFORMANCE_DIR ??
    join(HERE, "..", "..", "..", "..", "certcrypt-conformance", "fixtures");
  const dir = join(base, "primitives");
  return existsSync(dir) ? dir : null;
}

function loadVectors(family: string): any | null {
  const dir = primitivesDir();
  if (dir === null) return null;
  return JSON.parse(readFileSync(join(dir, family, "vectors.json"), "utf-8"));
}

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

test("M′ framing matches the contract byte-for-byte", () => {
  const v = loadVectors("composite-m-prime");
  if (v === null) return; // absence is reported by the conformance runner, loudly

  for (const vec of v.vectors) {
    const m = compositeMPrime(vec.composite_alg_id, vec.payload_canon_digest_hex);
    assert.equal(
      toHex(m),
      vec.expected_m_prime_hex,
      `composite-m-prime '${vec.label}': framing diverged — domain prefix, separators, ` +
        `or the order of the parts`
    );
    assert.equal(
      m.length,
      vec.expected_m_prime_len,
      `composite-m-prime '${vec.label}': length diverged`
    );
  }
});

test("the composite profile changes M′", () => {
  // The property the profile is in the framing FOR: without it, a signature made
  // under one profile could be reinterpreted under another.
  const digest = "a".repeat(64);
  assert.notDeepEqual(
    toHex(compositeMPrime(PROFILE_P256_MLDSA65, digest)),
    toHex(compositeMPrime(PROFILE_ED25519_MLDSA65, digest)),
    "omitting the profile from the framing makes a signature reinterpretable across profiles"
  );
});

test("every refusal in the contract's table is a refusal here", () => {
  const v = loadVectors("composite-verification");
  if (v === null) return;

  const keys = {
    classicalPubB64: v.system_domain_p256_public_key_b64,
    mldsaPubB64: v.system_domain_mldsa_public_key_b64,
  };

  let accepted = 0;
  let refused = 0;
  for (const c of v.cases) {
    const sig = c.signature as CompositeSignatureWire;
    // A case may present the classical key in another encoding: the same key,
    // other bytes, which the field's single encoding rule must refuse.
    const caseKeys = c.classical_public_key_b64
      ? { ...keys, classicalPubB64: c.classical_public_key_b64 }
      : keys;
    const got = verifyComposite(
      c.expected_composite_alg_id,
      v.payload_canon_digest_hex,
      sig,
      caseKeys
    );

    if (c.expected_outcome === "accepted") {
      accepted++;
      // Without an ML-DSA backend registered, the post-quantum half is not
      // CHECKED — the toolkit reports `performed: false` and fails closed. That
      // is the correct answer to "can this be trusted?", and it is a different
      // fact from a signature being wrong. Asserting `valid === true` here would
      // demand the toolkit trust an unverified component, so the assertion is on
      // the classical half, which this runtime can check.
      if (got.mldsa.performed === false) {
        assert.equal(
          got.classical.passed,
          true,
          `case '${c.label}': the classical half of a valid composite must verify`
        );
        continue;
      }
      assert.equal(
        got.valid,
        true,
        `case '${c.label}': this toolkit rejects a composite the contract pins as valid`
      );
    } else {
      refused++;
      assert.equal(
        got.valid,
        false,
        `case '${c.label}': this toolkit ACCEPTS a composite the contract refuses — ${c.why}`
      );
    }
  }

  // A table of only-positives, or only-negatives, would pass vacuously while
  // pinning nothing about the boundary between them.
  assert.ok(
    accepted >= 1 && refused >= 1,
    `the refusal table must carry both a valid case and refusals ` +
      `(accepted=${accepted}, refused=${refused})`
  );
});

test("the post-quantum floor is refused when absent", () => {
  // Called out on its own because it is the one refusal no cryptographic check
  // makes for you: the classical half of this case verifies perfectly.
  const v = loadVectors("composite-verification");
  if (v === null) return;

  const c = v.cases.find((x: any) => x.label === "missing-mldsa-component");
  assert.ok(c, "the contract must carry the missing-PQC case");
  const got = verifyComposite(
    c.expected_composite_alg_id,
    v.payload_canon_digest_hex,
    c.signature as CompositeSignatureWire,
    {
      classicalPubB64: v.system_domain_p256_public_key_b64,
      mldsaPubB64: v.system_domain_mldsa_public_key_b64,
    }
  );
  assert.equal(got.valid, false, "a composite without its ML-DSA component must be refused");
  assert.notEqual(
    got.mldsa.passed,
    true,
    "the ML-DSA component cannot have passed — it was never there to check"
  );
});
