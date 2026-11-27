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
 * `verifyFoundation` on the shapes system-foundation/1 §6 and system-manifest/1
 * §6–§7 close: every object has exactly its members, identifiers and timestamps
 * have their one format, and every P-256 key is a 65-byte SEC1 uncompressed
 * point. Plus the shipped production statement, which must validate against
 * the pins of the published profile.
 *
 * The mutations run on the published F001 foundation from a sibling
 * `certcrypt-conformance` checkout; absent it, those tests skip. A mutation of
 * the signed payload fails on its shape before the signatures are read, which
 * is what each case asserts.
 */
import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { foundationPayloadDigest, verifyFoundation } from "./verify-foundation.js";
import { ResultBuilder } from "../result/builder.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import { getCertcryptConfig } from "../config/default.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { SystemFoundation } from "../types/foundation.js";
import type { SystemDomainConfig } from "../types/config.js";
import type { VerifierRequest } from "../types/request.js";

const here = dirname(fileURLToPath(import.meta.url));
const F001 = join(
  here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures",
  "conformance", "F001", "artifacts", "system-foundation.json",
);
const skip = existsSync(F001) ? false : `conformance fixtures not found (looked for ${F001})`;

const REQ: VerifierRequest = {
  verification_target_requested: "independent",
  input_mode: "artifact_set",
};

function run(
  foundation: unknown,
  config: SystemDomainConfig = getConformanceConfig(),
): { ok: boolean; failed: string[]; detail: string } {
  const builder = new ResultBuilder(REQ);
  const fp = verifyFoundation(foundation as SystemFoundation, config, builder);
  const r = builder.build();
  return {
    ok: fp !== null,
    failed: r.failed_check_ids.filter((id) => id.startsWith("FOUNDATION_")),
    detail: `${r.failure_reason ?? ""} ${JSON.stringify(r.failed_check_ids)}`,
  };
}

/** The P-256 point of a 65-byte SEC1 key, compressed to 33 bytes: same key, other bytes. */
function compress(b64: string): string {
  const u = Buffer.from(b64, "base64");
  const prefix = (u[64] & 1) === 1 ? 0x03 : 0x02;
  return Buffer.concat([Buffer.from([prefix]), u.subarray(1, 33)]).toString("base64");
}

describe("system-foundation/1 closed shapes", { skip }, () => {
  let base: Record<string, any>;
  const clone = () => JSON.parse(JSON.stringify(base));

  before(async () => {
    await initMlDsa65();
    base = JSON.parse(readFileSync(F001, "utf-8"));
  });

  it("the published foundation validates", () => {
    const r = run(base);
    assert.equal(r.ok, true, r.detail);
  });

  const rejects = (label: string, mutate: (f: Record<string, any>) => void, check: string) =>
    it(label, () => {
      const f = clone();
      mutate(f);
      const r = run(f);
      assert.equal(r.ok, false, `${label}: accepted`);
      assert.deepEqual(r.failed, [check], r.detail);
    });

  rejects("a statement member the profile does not define",
    (f) => { f.statement_note = "x"; }, "FOUNDATION_PROFILE_VALID");
  rejects("a foundation_statement_id outside its format",
    (f) => { f.foundation_statement_id = "has space"; }, "FOUNDATION_PROFILE_VALID");
  rejects("a statement_issued_at without the Z designator",
    (f) => { f.statement_issued_at = "2026-04-12T00:00:00+00:00"; }, "FOUNDATION_PROFILE_VALID");
  rejects("a manifest member the profile does not define",
    (f) => { f.system_manifest.note = "x"; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("an entry member the profile does not define",
    (f) => { f.system_manifest.entries[0].note = "x"; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a quorum member the profile does not define",
    (f) => { f.system_manifest.entries[0].quorum.t = 1; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a member object with an extra member",
    (f) => { f.system_manifest.entries[0].members[0].role = "x"; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("an empty entry kid",
    (f) => { f.system_manifest.entries[0].kid = ""; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a valid_from without the Z designator",
    (f) => { f.system_manifest.entries[0].valid_from = "2026-04-10T00:00:00"; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a bootstrap manifest at sequence 1",
    (f) => { f.system_manifest.manifest_sequence = 1; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a quorum with k = 1",
    (f) => { f.system_manifest.entries[0].quorum.k = 1; }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a member key in compressed SEC1 form",
    (f) => {
      const m = f.system_manifest.entries[0].members[0];
      m.public_key_p256_b64 = compress(m.public_key_p256_b64);
    }, "FOUNDATION_FINGERPRINT_RECOMPUTED");
  rejects("a Level-1 key in compressed SEC1 form",
    (f) => {
      f.system_domain_capacity_key_p256_b64 = compress(f.system_domain_capacity_key_p256_b64);
    }, "FOUNDATION_SIGNATURE_VALID");
  rejects("a Level-1 ML-DSA key of the wrong length",
    (f) => { f.system_domain_capacity_key_mldsa_b64 = Buffer.alloc(1951).toString("base64"); },
    "FOUNDATION_SIGNATURE_VALID");
  rejects("a statement_signatures element with an extra member",
    (f) => { f.statement_signatures[0].note = "x"; }, "FOUNDATION_SIGNATURE_VALID");

  it("published_rules_versions is checked for shape only — its content gates nothing", () => {
    // verifyFoundation takes no rules version: the list is metadata
    // (system-foundation/1 §6). Being part of the signed payload, its shape is
    // still checked.
    const f = clone();
    f.published_rules_versions = [42];
    const r = run(f);
    assert.deepEqual(r.failed, ["FOUNDATION_PROFILE_VALID"], r.detail);
  });

  it("the payload digest ignores the members outside the signed payload", () => {
    const f = clone();
    f.publication_refs = [{ publication_profile_id: "x", publication_reference: "y" }];
    assert.equal(foundationPayloadDigest(f as SystemFoundation), foundationPayloadDigest(base as SystemFoundation));
  });
});

describe("the shipped production statement", () => {
  before(async () => {
    await initMlDsa65();
  });

  it("validates, and matches every pin of the published profile", () => {
    const config = getCertcryptConfig();
    const statement = config.foundation_statement;
    assert.ok(statement, "the published profile ships the bootstrap statement");
    const builder = new ResultBuilder(REQ);
    const fp = verifyFoundation(statement, config, builder);
    assert.equal(fp, config.system_root_fingerprint);
    assert.equal(statement.foundation_statement_id, config.foundation_statement_id);
    assert.equal(foundationPayloadDigest(statement), config.foundation_payload_digest);
  });
});
