// Copyright © 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

/**
 * Non-production profiles — deliberately outside the published package.
 *
 * WHY THEY ARE NOT IN `core/`
 *
 * Shipping deployment identifiers inside a verifier package would publish them
 * as something to build against. Nothing here is a secret, but that is the part
 * that cannot be walked back: once a deployment is reachable from a published
 * artifact, someone integrates with it and withdrawing it becomes a breaking
 * change rather than housekeeping.
 *
 * HOW THE HARNESS USES THEM
 *
 * Write one to JSON and hand it to the CLI:
 *
 *   node dist/cli/certcrypt-verify.js --test-config ./my-deployment.json \
 *     --test-root-fingerprint <root> --request ...
 *
 * `verify()` still reports `production_verification: false` for any of them: the
 * flag compares the ENTIRE config against the published production profile, so a
 * test verdict cannot be relabelled as production by substituting fields.
 */
import type { SystemDomainConfig } from "../core/types/index.js";
import {
  TEST_CORPUS_ROOT,
  TEST_FOUNDATION_PAYLOAD_DIGEST,
  TEST_ROOT_FINGERPRINT,
} from "../core/config/test-keys.js";
import { RULES_2026_01_SUBJECT_PROFILES } from "../core/config/default.js";
import { PROFILE_P256_MLDSA65 } from "../core/crypto/composite.js";

// XRPL network identities. XRPL has no chain id: `server_info` reports a
// `network_id` (0 mainnet, 1 testnet), so the profile carries a namespaced
// identity derived from it. Compare for equality; never parse.
const XRPL_CONFORMANCE_CHAIN_ID = "xrpl-network-conformance";

/**
 * A deployment profile — read from the environment, never committed.
 *
 * `getConformanceConfig` below carries synthetic values: it describes no
 * deployment, so it lives in git safely. This one describes a deployment you
 * operate, so the SHAPE is here and the VALUES are not. Copy `.env.example`, fill
 * in your own accounts, and source it:
 *
 *   cp .env.example .env.local
 *   $EDITOR .env.local
 *   set -a; . ./.env.local; set +a
 *
 * This follows the repository's existing convention (`.gitignore` already keeps
 * `.env*` out and `.env.example` in) rather than inventing a parallel mechanism.
 * As that file says: this toolkit holds no secrets — it verifies and cannot
 * produce a signature. Deployment profiles are kept out of git because they
 * belong to whoever operates the deployment, not to the verifier.
 *
 * `.env.example` is the template for running this verifier against ANY
 * deployment: your own issuance, your own settlement account, your own rules
 * domain. The toolkit is verification infrastructure, not a client for one
 * system — `verify()` takes any `SystemDomainConfig`, the type is public, and
 * nothing here is privileged.
 *
 * Throws rather than defaulting: a harness silently verifying against a
 * deployment nobody chose produces results that look fine and mean nothing.
 */
export function getEnvConfig(): SystemDomainConfig {
  const need = (name: string): string => {
    const v = process.env[name];
    if (!v) {
      throw new Error(
        `${name} is not set. Copy .env.example, fill in YOUR deployment's values ` +
          `and source it. No deployment configuration ships with this repository.`
      );
    }
    return v;
  };
  return {
    system_id: need("CERTCRYPT_VERIFY_SYSTEM_ID"),
    system_root_fingerprint: need("CERTCRYPT_VERIFY_SYSTEM_ROOT_FINGERPRINT"),
    supported_rules_versions: need("CERTCRYPT_VERIFY_RULES_VERSIONS")
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    // `<rules_version>=<subtree_root>` pairs, comma-separated. Required: an
    // env-driven profile that omitted a commitment would be a verifier configured
    // to accept any corpus as the rules text, which rules-domain/1 §13.3.1
    // forbids. So it throws on a malformed pair rather than defaulting.
    rules_corpus_roots: Object.fromEntries(
      need("CERTCRYPT_VERIFY_RULES_CORPUS_ROOTS")
        .split(",")
        .map((pair) => pair.trim())
        .filter(Boolean)
        .map((pair) => {
          const at = pair.indexOf("=");
          if (at <= 0 || at === pair.length - 1) {
            throw new Error(
              "CERTCRYPT_VERIFY_RULES_CORPUS_ROOTS: expected " +
                `<rules_version>=<subtree_root> pairs, got "${pair}"`
            );
          }
          return [pair.slice(0, at).trim(), pair.slice(at + 1).trim()];
        })
    ),
    foundation_statement_id: need("CERTCRYPT_VERIFY_FOUNDATION_STATEMENT_ID"),
    foundation_payload_digest: need("CERTCRYPT_VERIFY_FOUNDATION_PAYLOAD_DIGEST"),
    admitted_subject_profiles: need("CERTCRYPT_VERIFY_SUBJECT_PROFILES")
      .split(",")
      .map((v) => v.trim())
      .filter(Boolean),
    signature_profile: need("CERTCRYPT_VERIFY_SIGNATURE_PROFILE"),
    settlement_profile_id: need("CERTCRYPT_VERIFY_SETTLEMENT_PROFILE_ID"),
    xrpl_chain_id: need("CERTCRYPT_VERIFY_XRPL_CHAIN_ID"),
    xrpl_mpt_issuance_id: need("CERTCRYPT_VERIFY_XRPL_MPT_ISSUANCE_ID"),
    xrpl_settlement_account: need("CERTCRYPT_VERIFY_XRPL_SETTLEMENT_ACCOUNT"),
    // PROTOCOL, not deployment: fixed by the settlement binding (the anchor prefix) and the XRPL
    // settlement profile (the symbol, and the fact that a rules domain must not
    // define an action-name parameter at all — XRPL has no named actions).
    // Reading them from the environment would invite redefining what the
    // specification forbids redefining.
    xrpl_action_name: "payment",
    xrpl_token_symbol: "CERT",
    xrpl_memo_prefix: "ccab1:",
    commitment_ttl_seconds: Number(
      process.env.CERTCRYPT_VERIFY_COMMITMENT_TTL_SECONDS ?? 86400
    ),
  };
}

/**
 * Conformance config — `rules/conformance`, the environment-agnostic contract.
 *
 * The conformance fixtures exercise the PROTOCOL MECHANICS (leaf hashing,
 * inclusion proofs, bindings, fail-closed cases), not any operational
 * environment. They carry `rules/conformance` so they are independent of any
 * deployment — a verifier of any environment can run them under this config.
 * Synthetic test root. Signatures are verified exactly as under any other
 * profile: there is no mode that accepts a signature without verifying it.
 */
export function getConformanceConfig(): SystemDomainConfig {
  return {
    system_id: "certcrypt",
    system_root_fingerprint: TEST_ROOT_FINGERPRINT,
    // `rules/conformance-uncommitted` is declared supported on purpose and given
    // NO entry below. It is the V042 vector: a rules domain a verifier claims to
    // support while holding no certified corpus commitment for it, which
    // rules-domain/1 §13.3.1 requires to fail closed. Without a supported-but-
    // uncommitted version there is no way to exercise that check — an unsupported
    // version fails earlier, on selection, and never reaches it.
    supported_rules_versions: ["rules/conformance", "rules/conformance-uncommitted"],
    rules_corpus_roots: { "rules/conformance": TEST_CORPUS_ROOT },
    foundation_statement_id: "test-foundation-P001-zero-data",
    foundation_payload_digest: TEST_FOUNDATION_PAYLOAD_DIGEST,
    admitted_subject_profiles: RULES_2026_01_SUBJECT_PROFILES,
    signature_profile: PROFILE_P256_MLDSA65,
    settlement_profile_id: "settlement.aggregated.xrpl/1",
    xrpl_chain_id: XRPL_CONFORMANCE_CHAIN_ID,
    xrpl_settlement_account: "rCONFORMANCEpOOLaccountXXXXXXXXXXXX",
    xrpl_mpt_issuance_id: "00000000C1F0A0E6E5F1D7B4A9C8E3F2D1B0A9C8E7F6D5C4",
    xrpl_action_name: "payment",
    xrpl_token_symbol: "CERT",
    xrpl_memo_prefix: "ccab1:",
    commitment_ttl_seconds: 2592000, // matches the P001 fixture window (30d)
  };
}
