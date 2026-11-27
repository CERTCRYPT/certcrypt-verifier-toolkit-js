import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { getConformanceConfig } from "../../harness/profiles.js";
import { PENDING_CORPUS_PROOF } from "../config/default.js";
import { initMlDsa65 } from "../crypto/ml-dsa.js";
import type { SystemDomainConfig } from "../types/index.js";
import type { VerifierRequest } from "../types/request.js";
import { verifyCertifiedFiles, verifyRulesCorpus, type RulesCorpusDocument } from "./verify-corpus.js";

// P007 is a published conformance positive whose certificate commits to one
// subject.collection/1 of three leaves, with the leaf material delivered. Its leaves
// are binary, not text, which is exactly what lets it test the whole chain: every
// link holds except the one that requires a corpus to be text.
const here = dirname(fileURLToPath(import.meta.url));
const P007 = join(here, "..", "..", "..", "..", "certcrypt-conformance", "fixtures", "conformance", "P007");
const skip = existsSync(P007)
  ? false
  : `conformance fixtures not found: check out certcrypt-conformance as a sibling (looked for ${P007})`;

const art = (name: string) => JSON.parse(readFileSync(join(P007, "artifacts", name), "utf-8"));

function request(): VerifierRequest {
  return {
    verification_target_requested: "independent",
    input_mode: "artifact_set",
    base_certificate: art("base-certificate.json"),
    independence_proof: art("independence-proof.json"),
    settlement_material: art("settlement-material.json"),
    capacity_evidence: art("capacity-evidence.json"),
    commitment_inclusion_proof: art("commitment-inclusion-proof.json"),
    system_foundation: art("system-foundation.json"),
  };
}

function documents(): RulesCorpusDocument[] {
  return ["leaf-0-0.bin", "leaf-0-1.bin", "leaf-0-2.bin"].map((name) => ({
    path: name,
    bytes: new Uint8Array(readFileSync(join(P007, "material", name))),
  }));
}

/** The conformance profile, carrying `commitment` as the corpus commitment of its rules domain. */
function carrying(commitment: string): SystemDomainConfig {
  const config = getConformanceConfig();
  const [rules] = config.supported_rules_versions;
  return { ...config, rules_corpus_roots: { ...config.rules_corpus_roots, [rules]: commitment } };
}

describe("rules corpus authenticity (rules-domain/1 §13.3)", { skip }, () => {
  before(async () => {
    await initMlDsa65();
  });
  const anchored = () => art("independence-proof.json").subtree_root as string;

  it("every link holds except the text requirement: the leaves recompute and fold to the signed root", () => {
    const result = verifyRulesCorpus(request(), documents(), carrying(anchored()));
    assert.equal(result.verdict.result_code, "INDEPENDENT_VALID");
    assert.equal(result.subtree_root, anchored());
    assert.equal(result.declared_cardinality, 3);
    assert.equal(result.valid, false);
    assert.deepEqual(
      result.failures.length,
      1,
      `only the text-profile link may fail for P007: ${result.failures.join(" | ")}`,
    );
    assert.match(result.failures[0], /subject\.text\/1/);
  });

  it("a proof that is not the one the verifier carries is refused, however valid it is", () => {
    const other = "0".repeat(64);
    const result = verifyRulesCorpus(request(), documents(), carrying(other));
    assert.equal(result.verdict.result_code, "INDEPENDENT_VALID");
    assert.ok(result.failures.some((f) => f.includes("is not the commitment this configuration carries")));
  });

  it("a verifier holding no commitment, or the pending-corpus-proof marker, accepts no corpus proof", () => {
    const result = verifyRulesCorpus(request(), documents(), carrying(PENDING_CORPUS_PROOF));
    assert.equal(result.valid, false);
    assert.ok(result.failures.some((f) => f.includes("carries no corpus commitment")));
  });

  it("an altered document is named, by position", () => {
    const docs = documents();
    docs[1] = { path: docs[1].path, bytes: new Uint8Array([...docs[1].bytes, 0x0a]) };
    const result = verifyRulesCorpus(request(), docs, carrying(anchored()));
    assert.ok(result.failures.some((f) => f.startsWith("document 1 (leaf-0-1.bin)")));
  });

  it("a missing document is a cardinality failure, never a partial pass", () => {
    const result = verifyRulesCorpus(request(), documents().slice(0, 2), carrying(anchored()));
    assert.ok(result.failures.some((f) => f.startsWith("cardinality mismatch")));
  });
});


describe("verifyCertifiedFiles", { skip }, () => {
  before(async () => {
    await initMlDsa65();
  });

  it("binary leaves: the whole chain holds for the exact files", () => {
    const result = verifyCertifiedFiles(request(), documents(), getConformanceConfig());
    assert.equal(result.verdict.result_code, "INDEPENDENT_VALID");
    assert.deepEqual(result.failures, []);
    assert.equal(result.valid, true);
    assert.equal(result.declared_cardinality, 3);
  });

  it("one changed byte is named, by position", () => {
    const files = documents();
    files[1] = { path: files[1].path, bytes: new Uint8Array([...files[1].bytes, 0x0a]) };
    const result = verifyCertifiedFiles(request(), files, getConformanceConfig());
    assert.equal(result.valid, false);
    assert.ok(result.failures.some((f) => f.startsWith("file 1 (leaf-0-1.bin)")));
  });

  it("reordered files fail: order is part of what is certified", () => {
    const files = documents();
    const result = verifyCertifiedFiles(request(), [files[1], files[0], files[2]], getConformanceConfig());
    assert.equal(result.valid, false);
  });

  it("a missing file is a cardinality failure, never a partial pass", () => {
    const result = verifyCertifiedFiles(request(), documents().slice(1), getConformanceConfig());
    assert.ok(result.failures.some((f) => f.startsWith("cardinality mismatch")));
  });
});
