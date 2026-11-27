/**
 * Element inclusion from the certificate alone (verifier-toolkit/1 §8.4.2),
 * driven by the shared vector `primitives/collection-merkle/certificate-element.json`
 * of certcrypt-conformance: signed certificates of the conformance domain, one
 * leaf value per case, and the outcome a toolkit must reach.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyCollectionElementFromCertificate } from "./verify-collection-element.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { BaseCertificate } from "../types/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTOR = process.env.CERTCRYPT_CONFORMANCE_DIR
  ? join(process.env.CERTCRYPT_CONFORMANCE_DIR, "primitives", "collection-merkle", "certificate-element.json")
  : join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives",
      "collection-merkle", "certificate-element.json");

interface Case {
  name: string;
  certificate: string;
  value_utf8: string;
  expected: { outcome: string; matches: unknown[] };
}

test("collection element from the certificate: every shared case", async () => {
  assert.ok(existsSync(VECTOR), `missing conformance vector ${VECTOR}`);
  assert.ok(await initMlDsa65(), "the ML-DSA-65 backend is needed to verify the certificates");
  const doc = JSON.parse(readFileSync(VECTOR, "utf-8")) as {
    certificates: Record<string, BaseCertificate>;
    cases: Case[];
  };
  assert.ok(doc.cases.length > 0);
  for (const c of doc.cases) {
    const got = verifyCollectionElementFromCertificate(
      doc.certificates[c.certificate],
      new TextEncoder().encode(c.value_utf8),
      { config: getConformanceConfig() },
    );
    assert.equal(got.outcome, c.expected.outcome, `${c.name}: ${got.reason}`);
    assert.deepEqual(got.matches, c.expected.matches, c.name);
  }
});

test("collection element from the certificate: a subject index that is not a collection", async () => {
  await initMlDsa65();
  const doc = JSON.parse(readFileSync(VECTOR, "utf-8")) as {
    certificates: Record<string, BaseCertificate>;
  };
  const got = verifyCollectionElementFromCertificate(
    doc.certificates.A,
    new TextEncoder().encode("alpha"),
    { config: getConformanceConfig(), subjectIndex: 1 },
  );
  assert.equal(got.outcome, "rejected");
  assert.deepEqual(got.matches, []);
});
