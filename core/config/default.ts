import type { SystemDomainConfig } from "../types/index.js";
import { TEST_ROOT_FINGERPRINT } from "./test-keys.js";
import { PROFILE_P256_MLDSA65 } from "../crypto/composite.js";
import { CERTCRYPT_FOUNDATION_STATEMENT } from "./certcrypt-foundation.js";

// XRPL network identities.
//
// XRPL defines no chain id: `server_info` reports a `network_id` (0 mainnet,
// 1 testnet) and no genesis-hash identifier. The proof
// material still needs the field, so the profile carries a namespaced identity
// derived from the network id.
//
// It is an IDENTITY STRING: compare it for equality, never parse it. Its only
// normative job is to differ between networks, so material settled on testnet can
// never be accepted as mainnet.
/**
 * The marker a corpus commitment carries while the corpus proof of its rules
 * version is pending. Never a value: every check that reads a corpus commitment
 * treats it as absent.
 */
export const PENDING_CORPUS_PROOF = "<pending-corpus-proof>";

const XRPL_MAINNET_CHAIN_ID = "xrpl-network-0";

/** The subject profiles `rules/2026-01` admits (its Section 16), in its order. */
export const RULES_2026_01_SUBJECT_PROFILES: readonly string[] = [
  "subject.binary/1",
  "subject.text/1",
  "subject.email/1",
  "subject.collection/1",
  "subject.ai-decision/1",
  "subject.context-snapshot/1",
];
// The conformance domain settles on no real network and declares its own.
const XRPL_CONFORMANCE_CHAIN_ID = "xrpl-network-conformance";

/**
 * The published CERTCRYPT system-domain profile.
 *
 * Named for WHOSE it is, not called "default", because this toolkit is not a
 * CERTCRYPT client: `verify()` accepts any `SystemDomainConfig` and the type is
 * exported, so it verifies any deployment of this protocol — your own issuance,
 * your own settlement account, your own rules domain. What ships here is the
 * profile most callers will need, not the only one that works.
 *
 * WHY IT IS COMPILED IN RATHER THAN CONFIGURED
 *
 * A verifier must not be configurable into lying. If CERTCRYPT's root fingerprint
 * came from the environment, anyone could substitute their own and obtain
 * `INDEPENDENT_VALID` over fabricated material. Publishing the profile inside the
 * package is what makes a verdict independent of whoever runs the verifier —
 * the same reason browsers ship root CAs rather than reading them from a file.
 *
 * THE VALUES ARE THE PUBLISHED MAINNET ONES. `system_root_fingerprint` is the
 * bootstrap root of `certcrypt.foundation.bootstrap/2026-10-18` (kid
 * `certcrypt-root-2026-10-18-56bd4b`, recomputable from the published
 * `system-foundation/1`); `xrpl_mpt_issuance_id` and `xrpl_settlement_account`
 * are the CERT issuance and the aggregate pool account on XRPL mainnet. They
 * are the values the published registry entries carry.
 *
 * The bootstrap statement itself ships too (`foundation_statement`), so the
 * proof signature and the capacity binding verify without fetching the Level-1
 * key from anywhere. It is validated on every use against the root fingerprint,
 * the statement id and the payload digest below.
 *
 * `rules_corpus_roots["rules/2026-01"]` carries the `subtree_root` of the
 * corpus proof of `rules/2026-01`, emitted on 2026-11-26 and published in
 * certcrypt-specs under `verification/rules/rules-2026-01/`. A corpus root only exists
 * once the rules text is certified through a real emission; until then a rules
 * version carries `<pending-corpus-proof>`, which RULES_CORPUS_COMMITMENT_PRESENT
 * rejects. Writing a concrete value before its source exists is a fail-OPEN bug,
 * not a fix.
 */
export function getCertcryptConfig(): SystemDomainConfig {
  return {
    system_id: "certcrypt",
    system_root_fingerprint: "24a0ed1bc18463a060fd04ff255244b4512340696997c9c3fc9f3d3f3079f69a",
    supported_rules_versions: ["rules/2026-01"],
    rules_corpus_roots: {
      // The subtree_root of the corpus proof that certifies the final text of
      // rules/2026-01 (emitted 2026-11-26, verification/rules/rules-2026-01/).
      "rules/2026-01": "17e3a74a4fd05b039da9f740a138c36d353f561d49726c00351843bb518364ff",
    },
    foundation_statement_id: "certcrypt.foundation.bootstrap/2026-10-18",
    foundation_payload_digest: "d68370b6e6242478c0088a0b4aefa0055bbfba89009f64481157a704ce13468f",
    foundation_statement: CERTCRYPT_FOUNDATION_STATEMENT,
    admitted_subject_profiles: RULES_2026_01_SUBJECT_PROFILES,
    signature_profile: PROFILE_P256_MLDSA65,
    settlement_profile_id: "settlement.aggregated.xrpl/1",
    xrpl_chain_id: XRPL_MAINNET_CHAIN_ID,
    xrpl_settlement_account: "rEdGFQHY5VhadmVSHhxqWHNFVvfUw9XpMU",
    xrpl_mpt_issuance_id: "066AE75B79EAAC53741F55155550B40213F220B1EFD0F357",
    xrpl_action_name: "payment",
    xrpl_token_symbol: "CERT",
    xrpl_memo_prefix: "ccab1:",
    commitment_ttl_seconds: 86400, // rules/2026-01 — 24h
  };
}

