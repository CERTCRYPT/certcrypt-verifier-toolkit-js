import type { SystemFoundation } from "./foundation.js";

export interface SystemDomainConfig {
  system_id: string;
  system_root_fingerprint: string;
  supported_rules_versions: string[];
  /**
   * The certified corpus commitment of each supported rules domain: the
   * `subtree_root` that domain's corpus proof certifies over its normative
   * documents (`rules-domain/1` §13.3).
   *
   * Compiled in for the same reason as `system_root_fingerprint`, and it is the
   * same failure if it is not: a verifier must not be configurable into trusting
   * the wrong rules text. Read this from the environment, from a file, or from
   * the ruleset being evaluated, and anyone can substitute their own and obtain a
   * valid verdict over a corpus they wrote themselves.
   *
   * What it is FOR, since evaluation does not need it: the parameters below are
   * compiled in, so this verifier never reads the published specifications at
   * evaluation time. This value is what lets a third party confirm that those
   * compiled parameters are the ones the published corpus actually states — that
   * this build was not made against an altered registry entry. Without it, a
   * verifier built on tampered rules text is indistinguishable from an honest one.
   *
   * A rules version listed in `supported_rules_versions` with no entry here MUST
   * fail closed. Absence is not permission (`rules-domain/1` §13.3.1).
   */
  rules_corpus_roots: Record<string, string>;
  /**
   * The `foundation_statement_id` of the domain's bootstrap `system-foundation/1`
   * statement, exactly as its registry entry declares it. A statement that
   * carries any other id is not the registered bootstrap and is rejected, even
   * when its fingerprint and quorum verify.
   */
  foundation_statement_id: string;
  /**
   * SHA3-256(UTF-8(JCS(payload))) of the bootstrap statement's canonical unsigned
   * payload (`system-foundation/1` §9) — the value the bootstrap quorum signed —
   * exactly as the registry entry declares it. Pins every signed member of the
   * one bootstrap statement, the Level-1 capacity key included: a second
   * statement over the same manifest, even one the quorum signed, is rejected.
   */
  foundation_payload_digest: string;
  /**
   * The bootstrap statement itself, when the profile ships it. Used whenever a
   * request supplies no statement, and validated exactly like a supplied one,
   * against the three values above — shipping it removes the need to fetch it,
   * not the need to check it.
   */
  foundation_statement?: SystemFoundation;
  /**
   * The subject profiles the rules domain admits. A certificate subject — or a
   * leaf of a collection subject — that declares any other profile is
   * non-conformant and fails closed, rather than being reported as merely
   * unsupported.
   */
  admitted_subject_profiles: readonly string[];
  /**
   * The composite signature profile the rules domain fixes for the certificate
   * issuer signature, the Level-1 capacity-authorization binding and the
   * independence proof signature. The expected profile comes from here, never
   * from the artifact: a signature declaring another profile fails closed even
   * where it would verify under it.
   */
  signature_profile: string;
  settlement_profile_id: string;
  xrpl_chain_id: string;
  xrpl_mpt_issuance_id: string;
  /**
   * The account the settlement debits — the aggregate settlement account, never
   * an issuer's own.
   *
   * A parameter the RULES DOMAIN publishes, and that matters for longevity:
   * this account can rotate (a compromised key is rotated, not lived with), and
   * a certificate settled under the previous one must keep verifying forever. A
   * verifier takes it from the profile of the domain the certificate names, so
   * old evidence resolves against the parameters in force when it was settled.
   *
   * Empty is not "unconstrained": settlement verification fails closed when no
   * account is configured, because an empty value cannot express the constraint
   * this field exists for.
   */
  xrpl_settlement_account: string;
  /** Required settlement action under settlement.aggregated.xrpl/1: `payment`,
   *  an XRPL transaction type, not an action on a contract. Paying an MPT back
   *  to its issuer destroys that amount, so there is no sink account. */
  xrpl_action_name: string;
  xrpl_token_symbol: string;
  xrpl_memo_prefix: string;
  /**
   * Capacity-commitment TTL in seconds, from the active rules-domain registry
   * (e.g. `rules/2026-01` = 86400). The commitment's signed `expires_at`
   * MUST equal `issued_at + commitment_ttl_seconds`; the verifier enforces this
   * as `COMMITMENT_TTL_VALID`, so an issuer cannot inflate its own window (e.g.
   * emit `issued_at=today, expires_at=2100`). Public rule the verifier consumes.
   */
  commitment_ttl_seconds: number;
}
