import { before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PENDING_CORPUS_PROOF, getCertcryptConfig } from "./config/default.js";
import { getEnvConfig, getConformanceConfig } from "../harness/profiles.js";
import { verify } from "./verify.js";
import { initMlDsa65 } from "./crypto/ml-dsa.js";
import type { VerifierRequest } from "./types/request.js";

// A published conformance positive, read from the sibling checkout of
// certcrypt-conformance (not vendored: a copy would drift from the contract).
const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(
  here, "..", "..", "..",
  "certcrypt-conformance", "fixtures", "conformance", "P001", "artifacts"
);
const fixtureSkip = existsSync(FIXTURE)
  ? false
  : `conformance fixtures not found: check out certcrypt-conformance as a sibling of this repository (looked for ${FIXTURE})`;

function fixtureRequest(): VerifierRequest {
  const load = (name: string) => JSON.parse(readFileSync(join(FIXTURE, name), "utf-8"));
  return {
    verification_target_requested: "independent",
    input_mode: "artifact_set",
    base_certificate: load("base-certificate.json"),
    independence_proof: load("independence-proof.json"),
    settlement_material: load("settlement-material.json"),
    capacity_evidence: load("capacity-evidence.json"),
    commitment_inclusion_proof: load("commitment-inclusion-proof.json"),
    system_foundation: load("system-foundation.json"),
  };
}

/**
 * Non-production profiles live in harness/ and are not published. What keeps any
 * non-production config safe is that a result carries WHICH regime produced it:
 * `production_verification` is true only when the ENTIRE config equals the
 * published production profile. These tests pin that boundary, because the failure
 * mode is silent — a test verdict labeled production looks identical to a real
 * one.
 */
describe("production profile boundary", () => {
  const published = getCertcryptConfig();

  it("every published field is compared, not just the obvious ones", () => {
    // Guard against the drift that actually happens: a field is added to the
    // config and nobody adds it to the production-profile comparison, so a config
    // differing ONLY in that field passes as production. This asserts the
    // comparison covers every field the config declares.
    const compared = new Set([
      "system_root_fingerprint",
      "system_id",
      "xrpl_chain_id",
      "xrpl_mpt_issuance_id",
      "xrpl_settlement_account",
      "xrpl_token_symbol",
      "xrpl_action_name",
      "settlement_profile_id",
      "supported_rules_versions",
      // Compared per rules version: a config carrying a different corpus
      // commitment would accept a corpus other than the published one as the
      // rules text (rules-domain/1 §13.3.1).
      "rules_corpus_roots",
      // What the rules domain admits and how it signs: a config accepting other
      // subject profiles, another signature profile or another bootstrap
      // statement is not the published profile.
      "foundation_statement_id",
      "foundation_payload_digest",
      "admitted_subject_profiles",
      "signature_profile",
      // Not compared, and need not be: the shipped statement is validated on
      // every use against the root fingerprint, the statement id and the payload
      // digest above, so a config carrying another statement fails there.
      "foundation_statement",
      // Deliberately NOT compared: it is a rules-domain parameter, not part of
      // what identifies the operative environment.
      "xrpl_memo_prefix",
      "commitment_ttl_seconds",
    ]);
    for (const field of Object.keys(published)) {
      assert.ok(
        compared.has(field),
        `config field "${field}" is not accounted for in the production-profile ` +
          `comparison in verify.ts — either compare it, or add it here with the ` +
          `reason it is excluded`
      );
    }
  });

  it("the non-production profiles differ from production in at least one compared field", () => {
    // getEnvConfig reads a deployment profile the operator supplies; without one
    // there is nothing to compare, and that is the intended state for a fresh
    // clone. Skip rather than fail: the assertion below is about profile shape,
    // not about whether this machine has a deployment configured.
    const haveEnvProfile = Boolean(process.env.CERTCRYPT_VERIFY_SYSTEM_ID);
    // If a test profile matched production on every compared field, it would be
    // labeled production — which is the whole risk of shipping them.
    const profiles: Array<readonly [string, ReturnType<typeof getConformanceConfig>]> = [
      ["conformance", getConformanceConfig()],
    ];
    if (haveEnvProfile) profiles.push(["environment", getEnvConfig()] as const);
    for (const [name, cfg] of profiles) {
      const differs =
        cfg.system_root_fingerprint !== published.system_root_fingerprint ||
        cfg.system_id !== published.system_id ||
        cfg.xrpl_chain_id !== published.xrpl_chain_id ||
        cfg.xrpl_mpt_issuance_id !== published.xrpl_mpt_issuance_id ||
        cfg.xrpl_settlement_account !== published.xrpl_settlement_account ||
        cfg.settlement_profile_id !== published.settlement_profile_id ||
        cfg.supported_rules_versions.join() !== published.supported_rules_versions.join();
      assert.ok(
        differs,
        `${name} config is indistinguishable from production on every compared ` +
          `field, so its results would be labeled production_verification: true`
      );
    }
  });

  it("a deployment profile must be supplied, never defaulted", () => {
    // The failure mode this prevents: a harness silently verifying against some
    // built-in deployment produces results that look fine and mean nothing. With
    // no profile configured, getEnvConfig MUST throw rather than pick one.
    const saved = process.env.CERTCRYPT_VERIFY_SYSTEM_ID;
    delete process.env.CERTCRYPT_VERIFY_SYSTEM_ID;
    try {
      assert.throws(
        () => getEnvConfig(),
        /CERTCRYPT_VERIFY_SYSTEM_ID/,
        "with no profile configured, getEnvConfig must fail loudly"
      );
    } finally {
      if (saved !== undefined) process.env.CERTCRYPT_VERIFY_SYSTEM_ID = saved;
    }
  });

  // The capacity evidence carries a composite signature, so the ML-DSA-65 backend
  // must be loaded for the unmodified positive to verify at all.
  before(async () => {
    assert.ok(await initMlDsa65(), "@noble/post-quantum required");
  });

  // The two tests below are about BEHAVIOR, not about what the published profile
  // currently contains: whatever values a profile carries, an unset settlement
  // account and a non-derivable root fingerprint must reject, never pass and never
  // skip. They run the full verifier over a published conformance positive, so the
  // only difference from an accepted verdict is the one field each test changes.

  it("an empty settlement account makes settlement verification fail closed", { skip: fixtureSkip }, () => {
    // An empty string compares as "anything goes" if it is treated as an absent
    // constraint. It must instead be a failure of the settlement-binding check.
    assert.equal(verify(fixtureRequest(), getConformanceConfig()).result_code, "INDEPENDENT_VALID");
    const result = verify(fixtureRequest(), {
      ...getConformanceConfig(),
      xrpl_settlement_account: "",
    });
    assert.notEqual(result.result_code, "INDEPENDENT_VALID");
    assert.ok(
      result.failed_check_ids.includes("CAPACITY_BINDING_VALID"),
      `an unset settlement account must fail CAPACITY_BINDING_VALID, not skip it ` +
        `(failed: ${result.failed_check_ids.join(", ") || "none"})`
    );
  });

  it("a placeholder root fingerprint never matches a derived foundation", { skip: fixtureSkip }, () => {
    // A derived fingerprint is a SHA3-256 hex digest; a placeholder is not, so no
    // foundation can ever match one and the verdict is a rejection.
    assert.equal(verify(fixtureRequest(), getConformanceConfig()).result_code, "INDEPENDENT_VALID");
    const result = verify(fixtureRequest(), {
      ...getConformanceConfig(),
      system_root_fingerprint: "<placeholder>",
    });
    assert.equal(result.result_code, "REJECTED");
    assert.ok(
      result.failed_check_ids.includes("FOUNDATION_BOOTSTRAP_MATCHES_RULES"),
      `a placeholder root must fail FOUNDATION_BOOTSTRAP_MATCHES_RULES ` +
        `(failed: ${result.failed_check_ids.join(", ") || "none"})`
    );
  });

  it("a profile's shipped statement stands in for a missing one, and is held to the same pins", { skip: fixtureSkip }, () => {
    // The conformance foundation, shipped by the profile instead of supplied by
    // the request, gives the same verdict as when the request carries it.
    const { system_foundation, ...withoutFoundation } = fixtureRequest();
    const conformance = getConformanceConfig();
    assert.ok(system_foundation, "P001 carries a foundation");
    const shipped = { ...conformance, foundation_statement: system_foundation };
    assert.equal(verify(withoutFoundation, shipped).result_code, "INDEPENDENT_VALID");
    // Without one, the proof signature has no key to verify against.
    assert.equal(verify(withoutFoundation, conformance).result_code, "INCOMPLETE");
    // A shipped statement whose payload is not the pinned one fails like a
    // supplied one.
    const repinned = { ...shipped, foundation_payload_digest: "0".repeat(64) };
    const result = verify(withoutFoundation, repinned);
    assert.equal(result.result_code, "REJECTED");
    assert.deepEqual(result.failed_check_ids, ["FOUNDATION_BOOTSTRAP_MATCHES_RULES"]);
  });

  it("a corpus commitment that is still the pending-corpus-proof marker is rejected", { skip: fixtureSkip }, () => {
    // The placeholder is a non-empty string, so a presence check alone would
    // accept it and vouch for a rules text no certified corpus backs.
    const conformance = getConformanceConfig();
    const rules = conformance.supported_rules_versions[0];
    const result = verify(fixtureRequest(), {
      ...conformance,
      rules_corpus_roots: { ...conformance.rules_corpus_roots, [rules]: PENDING_CORPUS_PROOF },
    });
    assert.equal(result.result_code, "REJECTED");
    assert.ok(
      result.failed_check_ids.includes("RULES_CORPUS_COMMITMENT_PRESENT"),
      `a placeholder corpus commitment must fail RULES_CORPUS_COMMITMENT_PRESENT ` +
        `(failed: ${result.failed_check_ids.join(", ") || "none"})`
    );
  });

  it("the published profile carries its values in their exact shape", () => {
    // A placeholder or an empty account here is a profile not yet filled in;
    // a wrong shape is a typo no other check would see until real material
    // fails against it.
    assert.match(published.system_root_fingerprint, /^[0-9a-f]{64}$/);
    assert.match(published.xrpl_mpt_issuance_id, /^[0-9A-F]{48}$/);
    assert.match(published.xrpl_settlement_account, /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/);
    for (const v of published.supported_rules_versions) {
      const root = published.rules_corpus_roots[v];
      assert.ok(
        root === PENDING_CORPUS_PROOF || /^[0-9a-f]{64}$/.test(root),
        `the corpus commitment of ${v} is either the placeholder (rejected at ` +
          `verification) or a digest, never anything else: ${root}`
      );
    }
  });

  it("a supplied deployment profile does not collide with production", () => {
    if (!process.env.CERTCRYPT_VERIFY_SYSTEM_ID) return;
    // Material settled on one network must never be acceptable as another's, and
    // the chain id is what separates them.
    assert.notEqual(getEnvConfig().xrpl_chain_id, published.xrpl_chain_id);
  });
});
