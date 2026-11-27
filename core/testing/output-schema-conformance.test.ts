/**
 * The full VerifierResult this toolkit emits MUST conform to the frozen
 * normative output schema in the conformance repo
 * (certcrypt-conformance/schemas/output/verifier-result.schema.json). The
 * schema is the contract (README, "Authority of schemas"); the language-native
 * types are conveniences. This test runs every conformance/adversarial fixture
 * through verify() and validates the produced result against that schema, so a
 * result field added/renamed/retyped without a matching schema bump fails here.
 *
 * Input-side validation (every fixture request against the input schema) lives
 * in the conformance repo's generator (validate_schemas.py) — it needs no
 * verifier and is gated there.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, dirname, isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verify } from "../verify.js";
import { getConformanceConfig } from "../../harness/profiles.js";
import { validateAgainstSchema } from "./validate-against-schema.js";
import type { VerifierRequest } from "../types/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const toolkitRoot = join(here, "..", "..", "..");

function conformanceBase(): string | null {
  const env = process.env.CERTCRYPT_CONFORMANCE_DIR;
  if (env) return env;
  const sibling = join(toolkitRoot, "..", "certcrypt-conformance", "fixtures");
  return existsSync(join(sibling, "conformance")) ? sibling : null;
}

function resolveRequestPaths(r: VerifierRequest, dir: string): VerifierRequest {
  const rp = (p: string | undefined) =>
    p === undefined ? undefined : isAbsolute(p) ? p : resolve(dir, p);
  const out = { ...r } as Record<string, unknown>;
  for (const k of [
    "verification_package_path", "base_certificate_path", "independence_proof_path",
    "settlement_material_path", "capacity_evidence_path",
    "commitment_inclusion_proof_path", "system_foundation_path", "original_material_path",
  ]) {
    if (typeof out[k] === "string") out[k] = rp(out[k] as string);
  }
  return out as unknown as VerifierRequest;
}

test("every fixture's full VerifierResult conforms to the frozen output schema", () => {
  const base = conformanceBase();
  if (!base) {
    console.error("conformance repo not found alongside toolkit; skipping");
    return;
  }
  const schemaPath = join(
    base, "..", "schemas", "output", "verifier-result.schema.json",
  );
  if (!existsSync(schemaPath)) {
    console.error("output schema not found; skipping");
    return;
  }
  const schema = JSON.parse(readFileSync(schemaPath, "utf-8"));
  const conf = getConformanceConfig();

  let validated = 0;
  for (const cat of ["conformance", "adversarial"]) {
    const catDir = join(base, cat);
    if (!existsSync(catDir)) continue;
    for (const entry of readdirSync(catDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const dir = join(catDir, entry.name);
      const inputPath = join(dir, "input.json");
      if (!existsSync(inputPath)) continue;
      const request = resolveRequestPaths(
        JSON.parse(readFileSync(inputPath, "utf-8")), dir,
      );
      const result = verify(request, conf);
      const errors = validateAgainstSchema(result, schema);
      assert.equal(
        errors.length, 0,
        `${entry.name}: VerifierResult violates the frozen output schema:\n  ${errors.join("\n  ")}`,
      );
      validated++;
    }
  }
  assert.ok(validated >= 70, `expected >= 70 fixtures validated, got ${validated}`);
});
