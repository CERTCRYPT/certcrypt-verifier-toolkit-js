/**
 * Zero-data capacity evidence types (capacity.evidence/1), mirroring the
 * reference producer. Field order matters for the
 * signing-bytes of `ProjectedCommitment` and `Level1AuthorizationBinding`:
 * both are serialized insertion-ordered (NOT JCS), so these interfaces declare
 * fields in the exact canonical order and the serializers below build the JSON
 * in that order.
 */

import type { CompositeSignatureWire } from "../crypto/composite.js";

export const ZERO_DATA_PROFILE = "zero-data.unlinkable";

export interface Level1AuthorizationBinding {
  system_id: string;
  rules_version: string;
  system_root_fingerprint: string;
  authorized_role: string;
  authorization_issuer_kid: string;
  valid_from: string;
  valid_until: string;
  holder_key_set_root: string;
}

export interface ProjectedAuthorization {
  system_id: string;
  rules_version: string;
  system_root_fingerprint: string;
  authorized_role: string;
  authorization_issuer_kid: string;
  valid_from: string;
  valid_until: string;
  holder_key_set_root: string;
  level1_binding: Level1AuthorizationBinding;
  /** System-domain Level-1 COMPOSITE signature (CERTCRYPT Composite Signature Profile) over
   *  M'(profile, SHA3(level1_binding signing bytes)); AND. Wire object. */
  level1_signature: CompositeSignatureWire;
  authorization_pseudonym: string;
  holder_pseudonym: string;
}

export interface ProjectedCommitment {
  commitment_version: string;
  system_id: string;
  system_root_fingerprint: string;
  rules_version: string;
  authorization_pseudonym: string;
  holder_pseudonym: string;
  pool_pseudonym: string;
  certificate_commitment_digest: string;
  consumed_quantity: string;
  /**
   * Issuer-declared per-subject effective units (`submission-set/1`):
   * non-collection subject → "1", collection → its declared_cardinality. The
   * per-subject quantity the certificate declares; distinct from
   * consumed_quantity (the capacity actually consumed). Canonical
   * decimal/integer string. Part of the signed view — see
   * projectedCommitmentSigningBytes.
   */
  declared_effective_units: string;
  issued_at: string;
  expires_at: string;
}

export interface OperationKeyDisclosure {
  leaf_index: number;
  public_key_b64: string;
  inclusion_proof: string[];
  tree_size: number;
}

export interface CapacityEvidence {
  profile: string;
  operation_salt_hex: string;
  projected_authorization: ProjectedAuthorization;
  projected_commitment: ProjectedCommitment;
  operation_key: OperationKeyDisclosure;
  commitment_signature_b64: string;
}

/**
 * Canonical insertion-ordered bytes of the projected commitment (the message
 * the holder's leaf key signs). MUST match the reference
 * producer's signing bytes byte-for-byte. We build the object in declared order so JSON.stringify emits
 * keys in that order (NOT sorted — this is not JCS).
 */
export function projectedCommitmentSigningBytes(pc: ProjectedCommitment): Uint8Array {
  const ordered = {
    commitment_version: pc.commitment_version,
    system_id: pc.system_id,
    system_root_fingerprint: pc.system_root_fingerprint,
    rules_version: pc.rules_version,
    authorization_pseudonym: pc.authorization_pseudonym,
    holder_pseudonym: pc.holder_pseudonym,
    pool_pseudonym: pc.pool_pseudonym,
    certificate_commitment_digest: pc.certificate_commitment_digest,
    consumed_quantity: pc.consumed_quantity,
    declared_effective_units: pc.declared_effective_units,
    issued_at: pc.issued_at,
    expires_at: pc.expires_at,
  };
  return new TextEncoder().encode(JSON.stringify(ordered));
}

/**
 * Canonical insertion-ordered bytes of the Level-1 authorization binding (the
 * message the system-domain signs). MUST match the
 * reference producer's signing bytes.
 */
export function level1BindingSigningBytes(b: Level1AuthorizationBinding): Uint8Array {
  const ordered = {
    system_id: b.system_id,
    rules_version: b.rules_version,
    system_root_fingerprint: b.system_root_fingerprint,
    authorized_role: b.authorized_role,
    authorization_issuer_kid: b.authorization_issuer_kid,
    valid_from: b.valid_from,
    valid_until: b.valid_until,
    holder_key_set_root: b.holder_key_set_root,
  };
  return new TextEncoder().encode(JSON.stringify(ordered));
}
