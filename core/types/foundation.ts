/**
 * CERTCRYPT System Foundation Statement type definitions.
 * Per system-foundation/1.
 */

import type { CompositeSignatureWire } from "../crypto/composite.js";

export interface PublicationRef {
  publication_profile: string;
  publication_reference: string;
}

/** One authorized composite signing key of a manifest entry's quorum (system-manifest/1). */
export interface ManifestMember {
  member_kid: string;
  /** ECDSA P-256 SEC1 component public key, base64. */
  public_key_p256_b64: string;
  /** ML-DSA-65 FIPS 204 pkEncode component public key, base64. */
  public_key_mldsa_b64: string;
}

/** Quorum threshold of a manifest entry (system-manifest/1): 2 ≤ k ≤ n. */
export interface QuorumSpec {
  k: number;
  n: number;
}

/** One element of predecessor_signatures / statement_signatures: a member's composite signature. */
export interface MemberSignature {
  signer_member_kid: string;
  signature: CompositeSignatureWire;
}

/** One closed-schema entry of system-manifest/1 (10 members). */
export interface ManifestEntry {
  kid: string;
  algorithm: string;
  quorum: QuorumSpec;
  members: ManifestMember[];
  valid_from: string;
  valid_until: string | null;
  predecessor_kid: string | null;
  successor_kid: string | null;
  predecessor_signatures: MemberSignature[] | null;
  predecessor_manifest_fingerprint: string | null;
}

/** A system-manifest/1 instance (4 top-level members). */
export interface SystemManifest {
  manifest_profile_id: string;
  system_id: string;
  manifest_sequence: number;
  entries: ManifestEntry[];
}

export interface SystemFoundation {
  foundation_profile_id: string;
  foundation_statement_id: string;
  system_id: string;
  system_root_fingerprint: string;
  /**
   * The embedded system-manifest/1 bootstrap manifest version (sequence 0, one
   * entry, k-of-n composite quorum). system_root_fingerprint =
   * SHA3-256(JCS(system_manifest)) (system-manifest/1).
   */
  system_manifest: SystemManifest;
  /** Always "sha3-256-system-manifest-jcs-v1" under /1. */
  root_fingerprint_derivation: string;
  published_rules_versions: string[];
  statement_issued_at: string;
  /**
   * Quorum of bootstrap-member composite signatures over the unsigned payload.
   * At least entries[0].quorum.k DISTINCT members must verify (system-foundation/1
   * system-manifest/1 counting rule).
   */
  statement_signatures: MemberSignature[];
  publication_refs?: PublicationRef[];
  /**
   * System-domain Level-1 COMPOSITE key for the zero-data capacity anchor (CERTCRYPT Composite Signature Profile).
   * DISTINCT from the root quorum (which authorizes rotation/bootstrap): the
   * Level-1 key authorizes holder operation-key sets AND signs both the
   * capacity-evidence Level-1 binding and the Proof of Independence — all as a
   * composite, so the key is published as TWO component public keys.
   * REQUIRED and COVERED by the statement signatures: both fields are
   * part of the signed manifest payload, so they cannot be substituted without
   * invalidating FOUNDATION_SIGNATURE_VALID. Their authority is the bootstrap
   * quorum signature over the payload, NOT mere co-publication in the same JSON.
   */
  system_domain_capacity_key_p256_b64: string;
  system_domain_capacity_key_mldsa_b64: string;
  /**
   * Successor-binding observations attached to the statement
   * (system-foundation/1 §6, system-manifest/1 §12.5). NOT part of the signed
   * statement payload: each observation's only authority is the quorum of the
   * embedded bootstrap entry's members over its successor-binding payload (§9,
   * §12.3), which the verifier checks before the observation is compared or
   * counted.
   */
  successor_binding_observations?: SuccessorBindingObservationInput[];
}

/**
 * The canonical unsigned successor-binding payload (system-manifest/1 §9): the
 * exact object every element of `predecessor_signatures` signs, as
 * SHA3-256(UTF-8(JCS(payload))) under the composite profile.
 */
export interface SuccessorBindingPayload {
  binding_profile: string;
  system_id: string;
  predecessor_kid: string;
  predecessor_manifest_fingerprint: string;
  predecessor_manifest_sequence: number;
  successor_kid: string;
  successor_algorithm: string;
  successor_quorum: QuorumSpec;
  successor_members: ManifestMember[];
  successor_valid_from: string;
}

/** One successor-binding observation: the payload and the predecessor quorum over it. */
export interface SuccessorBindingObservationInput {
  successor_binding: SuccessorBindingPayload;
  predecessor_signatures: MemberSignature[];
}

/**
 * Canonical unsigned statement payload field order (system-foundation/1).
 * Canonicalization is RFC 8785 JCS (sorted keys, null members preserved), so
 * this listing order is human-readable only and does not affect the signed
 * bytes. The embedded system_manifest participates inline.
 */
export const FOUNDATION_UNSIGNED_PAYLOAD_FIELDS: (keyof SystemFoundation)[] = [
  "foundation_profile_id",
  "foundation_statement_id",
  "system_id",
  "system_root_fingerprint",
  "system_manifest",
  "root_fingerprint_derivation",
  // The Level-1 composite capacity key is COVERED by the statement signatures
  // — part of the signed manifest payload.
  "system_domain_capacity_key_p256_b64",
  "system_domain_capacity_key_mldsa_b64",
  "published_rules_versions",
  "statement_issued_at",
];
