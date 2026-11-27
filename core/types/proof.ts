import type { ComponentSignature } from "../crypto/composite.js";

export interface FinalityContext {
  /** Public, permissionless substrate that witnesses this finality (e.g. "xrpl").
   *  NEVER a trusted third party / TSA: finality is witnessed by a public substrate. */
  substrate: string;
  block_height: string;
  /** Irreversible block time of the settlement: the substrate's "when"
   *  for the capacity consumption. RFC 3339 UTC. */
  timestamp: string;
  confirmation_level: string;
}

export interface Settlement {
  profile_id: string;
  ref: string;
  /** Finality witnesses: a list so a second public substrate is additive
   *  later without a version bump. Under settlement.aggregated.xrpl/1: one
   *  element (XRPL). */
  finality_proofs: FinalityContext[];
}

export interface Batch {
  root: string;
  index: string;
  size: string;
}

export interface AntiReplay {
  nonce: string;
  derivation: string;
}

/**
 * Node attestation (independence.proof/1 §10.15): the system domain states,
 * inside the signed view, that the submission carrying this leaf entered through
 * the recognized node `node_id`, whose recognition it checked at `recognized_at`.
 */
export interface NodeAttestation {
  /** Stable node identifier: `op:` followed by 22 standard-base64 characters. */
  node_id: string;
  /** RFC 3339 UTC, whole seconds (`YYYY-MM-DDTHH:MM:SSZ`). Not a time seal. */
  recognized_at: string;
}

export interface IndependenceProof {
  proof_version: string;
  system_id: string;
  system_root_fingerprint: string;
  rules_version: string;
  /**
   * `SHA3-256(JCS(identity view))`, the identity view being exactly
   * `proof_version`, `system_id`, `rules_version`, `system_root_fingerprint`,
   * `subtree_root`, `closure_time`, `consumed_commitment_ids` and
   * `settlement_ref` (independence.proof/1 §10.3.1). The verifier recomputes it.
   */
  proof_id: string;
  /**
   * The leaf's bound value under the leaf=subtree model: the Merkle root over
   * the commitments accepted into this settlement leaf. A commitment's
   * `commitment_id` includes against this root (level 1); this root is itself a
   * leaf of the batch tree (level 2).
   */
  subtree_root: string;
  /** Submission-set close timestamp declared by the issuer side: RFC 3339 UTC,
   *  whole seconds. Not a CERTCRYPT time seal. */
  closure_time: string;
  /** Ordered consumed capacity.commitment/1 ids (64 lowercase hex, no duplicates). */
  consumed_commitment_ids: string[];
  /** Canonical settlement reference `chain_id:trx_id:action_ordinal:batch_id:window_id`. */
  settlement_ref: string;
  settlement: Settlement;
  batch: Batch;
  inclusion_proof: string[];
  anti_replay: AntiReplay;
  independence_result: string;
  /** `SHA3-256(JCS(proof with proof_digest = ""))` (independence.proof/1 §10.11). */
  proof_digest: string;
  /** Optional, signed when present (independence.proof/1 §10.15). */
  node_attestation?: NodeAttestation;
  created_at?: string;
  /**
   * Mandatory composite signature (ECDSA P-256 + ML-DSA-65) by the system-domain
   * Level-1 capacity key over the JCS of the signed view
   * (independence.proof/1 §10.13).
   */
  signature: ProofSignature;
}

/**
 * The proof signature object (independence.proof/1 §10.13): a composite
 * (ECDSA P-256 + ML-DSA-65) over the JCS of the signed view.
 */
export interface ProofSignature {
  signing_kid: string;
  /** Composite profile id (`alg`), `mode`, and ordered `signatures[]` are
   *  flattened in at this level (see CompositeSignatureWire). */
  alg: string;
  mode: string;
  signatures: ComponentSignature[];
}
