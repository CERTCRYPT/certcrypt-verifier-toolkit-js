/**
 * CCSP/1 envelope rules of the Issued path that the verdict fixtures do not each
 * pin: field formats and limits, and the canonical P-256 key encoding. Each
 * case mutates the positive C001 certificate of the conformance suite (which
 * carries every optional member) and runs the Issued path alone.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyIssued } from "./verify-issued.js";
import { ResultBuilder } from "../result/builder.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import type { BaseCertificate, LoadedArtifacts, VerifierRequest } from "../types/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const CERT = join(
  here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "conformance", "C001", "artifacts",
  "base-certificate.json",
);
const REQ: VerifierRequest = { verification_target_requested: "issued", input_mode: "artifact_set" };

function loadCert(): any | null {
  if (!existsSync(CERT)) {
    console.error("conformance C001 not found alongside toolkit; skipping");
    return null;
  }
  return JSON.parse(readFileSync(CERT, "utf-8"));
}

function run(cert: unknown): {
  failed: string[]; code: string | null; reason: string | null; issued: boolean;
} {
  const builder = new ResultBuilder(REQ);
  const artifacts = { baseCertificate: cert as BaseCertificate, originalMaterial: null } as LoadedArtifacts;
  verifyIssued(artifacts, getConformanceConfig(), builder);
  const r = builder.build();
  // Only the Issued checks ran; the request-level checks this harness skips are
  // left out of the comparison.
  const issuedChecks = ["BASE_CERTIFICATE_STRUCTURE_VALID", "BASE_CERTIFICATE_AUTHENTIC"];
  return {
    failed: r.failed_check_ids.filter((id) => issuedChecks.includes(id)),
    code: r.result_code,
    reason: r.failure_reason,
    issued: r.issued_valid,
  };
}

test("CCSP/1: the C001 certificate passes the Issued path unchanged", async () => {
  const cert = loadCert();
  if (!cert) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const r = run(cert);
  assert.deepEqual(r.failed, [], `unexpected failure: ${r.reason}`);
  assert.equal(r.issued, true);
});

const STRUCTURE_CASES: [string, (c: any) => void, RegExp][] = [
  ["issued_at on a day the month does not have", (c) => { c.payload.anchor.issued_at = "2026-02-30T00:00:00Z"; }, /issued_at/],
  ["issued_at with a lowercase z", (c) => { c.payload.anchor.issued_at = "2026-04-11T13:00:00z"; }, /issued_at/],
  ["issued_at with a leap second", (c) => { c.payload.anchor.issued_at = "2026-06-30T23:59:60Z"; }, /issued_at/],
  ["metadata that is not an object", (c) => { c.metadata = ["note"]; }, /metadata/],
  ["extensions that is not an object", (c) => { c.extensions = "x"; }, /extensions/],
  ["signer.id longer than 256 characters", (c) => { c.signatures[0].signer.id = "a".repeat(257); }, /signer\.id/],
  ["signer.id with a space", (c) => { c.signatures[0].signer.id = "issuer one"; }, /signer\.id/],
  ["kid longer than 128 characters", (c) => { c.signatures[0].kid = "k".repeat(129); }, /kid/],
  ["subject entry that is not an object", (c) => { c.payload.anchor.subjects[0] = "subject.binary/1"; }, /subjects\[0\]/],
  ["published payload digest in uppercase hex", (c) => { c.payload_canon_digest_hex = c.payload_canon_digest_hex.toUpperCase(); }, /payload_canon_digest_hex/],
  ["sig_target other than the payload digest", (c) => { c.signatures[0].sig_target = "anchor_canon_digest_hex"; }, /sig_target/],
  ["ECDSA component without low_s", (c) => { c.signatures[0].signatures[0].low_s = false; }, /low_s/],
  ["ML-DSA-65 component with an extra member", (c) => { c.signatures[0].signatures[1].encoding = "raw"; }, /component 1 members/],
  ["Ed25519 classical component", (c) => { c.signatures[0].signatures[0] = { alg: "Ed25519", sig_b64: "AAAA" }; }, /component 0 must be ECDSA/],
  ["role other than issuer", (c) => { c.signatures[0].role = "witness"; }, /role/],
];

for (const [name, mutate, reason] of STRUCTURE_CASES) {
  test(`CCSP/1: ${name} is REJECTED on structure`, () => {
    const cert = loadCert();
    if (!cert) return;
    mutate(cert);
    const r = run(cert);
    assert.equal(r.code, "REJECTED", name);
    assert.deepEqual(r.failed, ["BASE_CERTIFICATE_STRUCTURE_VALID"], name);
    assert.match(r.reason ?? "", reason, name);
  });
}

test("CCSP/1: a compressed P-256 key is malformed for pub_p256_b64, not an equivalent", async () => {
  const cert = loadCert();
  if (!cert) return;
  assert.ok(await initMlDsa65(), "ML-DSA-65 backend required");
  const raw = Buffer.from(cert.signatures[0].signer.pub_p256_b64, "base64");
  const compressed = Buffer.concat([Buffer.from([raw[64] & 1 ? 0x03 : 0x02]), raw.subarray(1, 33)]);
  cert.signatures[0].signer.pub_p256_b64 = compressed.toString("base64");
  const r = run(cert);
  assert.equal(r.code, "REJECTED");
  assert.deepEqual(r.failed, ["BASE_CERTIFICATE_AUTHENTIC"]);
  assert.match(r.reason ?? "", /SEC1 uncompressed/);
});
