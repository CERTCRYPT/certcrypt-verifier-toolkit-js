/**
 * Strict JSON parsing, checked against the certcrypt-conformance primitive
 * vectors (`fixtures/primitives/strict-json`): which documents parse, which are
 * refused, and which JSON subject materials are refused before canonicalization.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { strictJsonParse, StrictJsonError } from "./strict-json.js";
import { canonicalBytesForSubject } from "../crypto/canonical-subject.js";

const here = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(
  here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "primitives", "strict-json", "vectors.json",
);

function loadVectors(): any | null {
  if (!existsSync(VECTORS)) {
    console.error("strict-json conformance vectors not found alongside toolkit; skipping");
    return null;
  }
  return JSON.parse(readFileSync(VECTORS, "utf-8"));
}

test("strict-json: every case parses or is refused as the contract declares", () => {
  const v = loadVectors();
  if (!v) return;
  for (const c of v.cases) {
    let got: string;
    try {
      strictJsonParse(c.json_text);
      got = "ACCEPT";
    } catch (e) {
      assert.ok(e instanceof StrictJsonError, `case "${c.name}" threw a non-StrictJsonError`);
      got = "REJECTED";
    }
    assert.equal(got, c.expected, `strict-json case "${c.name}"`);
  }
});

test("strict-json: JSON subject material with a repeated member is refused before canonicalization", () => {
  const v = loadVectors();
  if (!v) return;
  for (const c of v.profile_material_cases) {
    const material = new TextEncoder().encode(c.material_utf8);
    let got: string;
    try {
      canonicalBytesForSubject(c.profile, material);
      got = "ACCEPT";
    } catch {
      got = "REJECTED";
    }
    assert.equal(got, c.expected_outcome, `material case "${c.name}"`);
  }
});

test("strict-json: an accepted document yields exactly the JSON.parse value", () => {
  const text = '{"a":[1,"x","x",{"b":null}],"__proto__":{"c":true},"n":-1.5e3}';
  assert.deepEqual(strictJsonParse(text), JSON.parse(text));
});

test("strict-json: nesting beyond the limit is refused, not truncated", () => {
  const deep = "[".repeat(600) + "]".repeat(600);
  assert.throws(() => strictJsonParse(deep), StrictJsonError);
});
