export interface SettlementAction {
  from: string;
  quantity: string;
  memo: string;
  contract: string;
  /** Action name the artifact declares. `payment` under
   *  settlement.aggregated.xrpl/1: paying an MPT back to its issuer destroys
   *  that amount, so there is no `to` account to name. */
  name: string;
  /** Chain ID for settlement_ref resolution per rules-domain/1 */
  chain_id: string;
  /** Transaction ID */
  trx_id: string;
  /** Action ordinal within the transaction */
  action_ordinal: string;
}

export interface FinalityProof {
  block_num: string;
  block_id: string;
  last_irreversible_block_num: string;
  last_irreversible_block_id: string;
  /** Irreversible block time of the settlement, RFC 3339 UTC: the
   *  substrate's "when" for the capacity consumption — the verdict's time
   *  authority, NOT a CERTCRYPT seal. */
  block_timestamp: string;
}

export interface BatchManifest {
  batch_id: string;
  window_id: string;
  leaf_count: string;
  total_quantity: string;
  settlement_root: string;
  system_id: string;
  rules_version: string;
  settlement_profile_id: string;
}

export interface CapacityConsumptionProof {
  total_quantity: string;
  leaf_quantity: string;
  token_symbol: string;
  token_contract: string;
}

export interface LeafPreimage {
  v: "ccab1-leaf";
  system_id: string;
  rules_version: string;
  settlement_profile_id: string;
  batch_id: string;
  leaf_index: string;
  /**
   * Leaf=subtree model: the Merkle root over the commitments accepted into
   * this leaf.
   */
  subtree_root: string;
  cost_commitment: string;
  consumed_quantity: string;
}

export interface BatchBindingPreimage {
  v: "ccab1";
  system_id: string;
  rules_version: string;
  settlement_profile_id: string;
  batch_id: string;
  window_id: string;
  leaf_count: string;
  total_quantity: string;
  settlement_root: string;
}

/**
 * Binds a leaf's `subtree_root` to its place in the batch tree (`subtree_root →
 * settlement_root`). The first inclusion level (`commitment → subtree_root`) is
 * carried per-commitment in `CommitmentInclusionProof`, not here — a leaf's
 * settlement material covers the leaf as a whole, not any single commitment.
 */
export interface SubmissionAssignmentProof {
  subtree_root: string;
  leaf_index: string;
  leaf_preimage: LeafPreimage;
  leaf_hash: string;
  sibling_hashes: string[];
}

/**
 * First level of the chained inclusion path: proves one commitment is a leaf of
 * the sub-tree whose root is `subtree_root`. Per-commitment material (one per
 * accepted commitment), delivered alongside the base certificate in the
 * `verification_package` (independence.proof/1).
 */
export interface CommitmentInclusionProof {
  commitment_id: string;
  commitment_leaf_hash: string;
  commitment_index: string;
  commitment_siblings: string[];
  subtree_size: string;
}

export interface AuthorizationBridgeProof {
  /**
   * SHA3-256 of the resolved Level-1 authorization's signing bytes — the same
   * digest the capacity evidence's `level1_binding` recomputes to. Identifies
   * the authorization without a correlating cleartext `issuer_scope`
   * (zero-data); the verifier cross-checks it against the evidence.
   */
  resolved_authorization_digest: string;
  cost_commitment: string;
  consumed_quantity: string;
  batch_binding_preimage: BatchBindingPreimage;
}

export interface CoherenceMaterial {
  system_id: string;
  rules_version: string;
  settlement_profile_id: string;
}

export interface SettlementMaterial {
  settlement_profile_id: string;
  settlement_action: SettlementAction;
  finality_proof: FinalityProof;
  batch_manifest: BatchManifest;
  capacity_consumption_proof: CapacityConsumptionProof;
  /** Leaf=subtree model: leaf bound to `subtree_root`. */
  submission_assignment_proof?: SubmissionAssignmentProof;
  /**
   * One authorization-bridge per DISTINCT resolved authorization present in the
   * leaf (settlement-material/1 §9). A leaf may group commitments under different Level-1
   * authorizations; the verifier selects the bridge whose
   * `resolved_authorization_digest` matches the evidence it is verifying, so every
   * accepted commitment can reconstruct its own authorization. All entries share
   * one `batch_binding_preimage` (the memo is batch-level, one per settlement).
   */
  authorization_bridge_proofs: AuthorizationBridgeProof[];
  coherence_material: CoherenceMaterial;
}
