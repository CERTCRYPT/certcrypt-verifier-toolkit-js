import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import {
  CONFORMANCE_VECTORS_VERSION,
  CONFORMANCE_FIXTURES_PASSED,
} from "./attestation.js";

/**
 * These tests defend the ONE property that makes the attestation worth
 * publishing: it cannot claim a version it did not earn.
 *
 * They deliberately do NOT assert "the version is 1.0.0". Pinning the expected
 * value here would recreate the hand-maintained string the whole mechanism
 * exists to eliminate — and would fail the suite on every legitimate conformance
 * bump. What is asserted instead is the INVARIANT: whatever the value is, it
 * agrees with the vectors actually on disk, and it is null when it cannot.
 */

const HERE = dirname(new URL(import.meta.url).pathname);
// dist/core/conformance -> dist/core -> dist -> toolkit root
const TOOLKIT_ROOT = join(HERE, "..", "..", "..");

function conformanceVersionOnDisk(): string | null {
  const envDir = process.env.CERTCRYPT_CONFORMANCE_DIR;
  const base =
    envDir && existsSync(envDir)
      ? join(envDir, "..")
      : join(TOOLKIT_ROOT, "..", "certcrypt-conformance");
  const versionPath = join(base, "VERSION");
  if (!existsSync(versionPath)) return null;
  const raw = readFileSync(versionPath, "utf-8").trim();
  return raw || null;
}

test("attestation is null or a non-empty version string — never a placeholder", () => {
  if (CONFORMANCE_VECTORS_VERSION === null) {
    assert.equal(
      CONFORMANCE_FIXTURES_PASSED,
      null,
      "fixture count must be null whenever the version is null: a count " +
        "without a contract version attests to nothing",
    );
    return;
  }
  assert.equal(typeof CONFORMANCE_VECTORS_VERSION, "string");
  assert.ok(
    CONFORMANCE_VECTORS_VERSION.length > 0,
    "an empty string is not a version; it must be null",
  );
  // Guard against the failure this module exists to prevent: a human-sounding
  // stand-in recorded as though it were a verified result.
  for (const placeholder of ["unknown", "unverified", "TBD", "latest", "null"]) {
    assert.notEqual(
      CONFORMANCE_VECTORS_VERSION.toLowerCase(),
      placeholder.toLowerCase(),
      `"${placeholder}" is not a conformance version — the absent case is null`,
    );
  }
  assert.ok(
    typeof CONFORMANCE_FIXTURES_PASSED === "number" &&
      CONFORMANCE_FIXTURES_PASSED > 0,
    "a recorded version must carry a positive fixture count: a version earned " +
      "by running zero fixtures is not earned",
  );
});

test("a recorded version matches the vectors present on disk", () => {
  if (CONFORMANCE_VECTORS_VERSION === null) return; // suite not run; nothing to cross-check

  const onDisk = conformanceVersionOnDisk();
  if (onDisk === null) return; // no checkout here to compare against (e.g. CI publish job)

  assert.equal(
    CONFORMANCE_VECTORS_VERSION,
    onDisk,
    "the attested vectors version disagrees with the certcrypt-conformance " +
      "checkout on disk. Either the vectors changed since the suite last ran " +
      "(re-run `npm run test:conformance`), or the attestation was edited by " +
      "hand — which it must never be.",
  );
});
