import type {
  IndependenceProof,
  SettlementMaterial,
  SystemDomainConfig,
} from "../types/index.js";
import type { BatchBindingPreimage, BatchManifest } from "../types/index.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import { level1BindingSigningBytes } from "../types/capacity-evidence.js";
import { parseCommitmentInstant } from "./capacity-evidence.js";
import { ResultBuilder } from "../result/builder.js";
import { digestHexBytes } from "../crypto/digest.js";
import { canonicalJsonBytes } from "../crypto/canonical-json.js";
import { computeLeafHash, verifyInclusionProof } from "../crypto/merkle.js";

/** The fields `batch_manifest` restates from `batch_binding_preimage`. */
type ManifestAnchoredField = keyof BatchManifest & keyof BatchBindingPreimage;

/**
 * Every field the manifest shares with the anchored preimage, derived from the
 * two types: the mapped type requires exactly one entry per shared key, so a
 * field added to both types fails to compile until it is listed here, and a
 * listed field that stops being shared fails as an excess property. Order is
 * the preimage's member order, so the first divergence reported is stable.
 */
const MANIFEST_ANCHORED_FIELD_SET: { [K in ManifestAnchoredField]: true } = {
  system_id: true,
  rules_version: true,
  settlement_profile_id: true,
  batch_id: true,
  window_id: true,
  leaf_count: true,
  total_quantity: true,
  settlement_root: true,
};

export const MANIFEST_ANCHORED_FIELDS = Object.keys(
  MANIFEST_ANCHORED_FIELD_SET
) as readonly ManifestAnchoredField[];

// XRPL settles with a `Payment` back to the token's own issuer: paying an MPT to
// its issuer destroys that amount, which is how supply ceases to exist on this
// substrate.
const REQUIRED_PROFILE = "settlement.aggregated.xrpl/1";
// The public substrate that witnesses finality under that profile: every
// finality witness of the proof names it (settlement.aggregated.xrpl/1 §11.3).
const REQUIRED_SUBSTRATE = "xrpl";

/**
 * Parse a settlement-action `quantity` string as a canonical `CERT,2` amount
 * and return its numeric portion (e.g. `"10.00 CERT"` -> `"10.00"`).
 *
 * The settlement amount is `CERT,2` — exactly two decimal places — and it
 * must be strictly positive. A loose `endsWith(" CERT")` + `split(" ")[0]`
 * would accept `"abc CERT"`, `"-1.00 CERT"`, `"0 CERT"`, `"1 CERT"`,
 * `"1.000 CERT"`, or a leading-zero `"01.00 CERT"` — any of which lets the
 * action diverge from the amount the settlement actually destroys (an amount
 * <= 0 or with non-`CERT,2` precision is never a valid settlement). This is the
 * exact grammar the reference producer emits and every conformant verifier
 * enforces:
 *
 *   `<int> "." <frac> " " "CERT"`
 *   - `<int>`:  one or more ASCII digits, no leading zeros unless the lone `0`
 *   - `<frac>`: EXACTLY two ASCII digits
 *   - decoded value strictly greater than zero
 *
 * Returns `{ numeric }` on success or `{ error }` with a parity message.
 */
function parseCert2Quantity(
  quantity: string,
  symbol: string
): { numeric: string } | { error: string } {
  const suffix = ` ${symbol}`;
  if (!quantity.endsWith(suffix)) {
    return {
      error: `quantity "${quantity}" is not a canonical ${symbol} asset (expected "<int>.<2-decimals> ${symbol}")`,
    };
  }
  const numeric = quantity.slice(0, quantity.length - suffix.length);

  const dot = numeric.indexOf(".");
  if (dot < 0) {
    return {
      error: `quantity "${quantity}" has no decimal point; ${symbol} is a 2-decimal asset (expected exactly 2 fractional digits)`,
    };
  }
  const intPart = numeric.slice(0, dot);
  const fracPart = numeric.slice(dot + 1);

  // Integer part: non-empty, all ASCII digits, no leading zeros (a lone "0" is
  // the only allowed zero-prefixed form).
  if (intPart.length === 0 || !/^[0-9]+$/.test(intPart)) {
    return { error: `quantity "${quantity}" has a non-numeric integer part` };
  }
  if (intPart.length > 1 && intPart.startsWith("0")) {
    return {
      error: `quantity "${quantity}" integer part "${intPart}" is not canonical (leading zero)`,
    };
  }

  // Fractional part: EXACTLY two ASCII digits (CERT,2 precision).
  if (fracPart.length !== 2 || !/^[0-9]{2}$/.test(fracPart)) {
    return {
      error: `quantity "${quantity}" must have exactly 2 fractional digits (${symbol},2)`,
    };
  }

  // Strictly positive: reject "0.00 CERT" (a no-op burn).
  if (/^0+$/.test(intPart) && fracPart === "00") {
    return { error: `quantity "${quantity}" is not strictly positive` };
  }

  return { numeric };
}

/**
 * Verify settlement under settlement.aggregated.xrpl/1.
 *
 * Checks: SETTLEMENT_REF_VALID, FINALITY_SUFFICIENT, CAPACITY_BINDING_VALID,
 *         CAPACITY_NOT_RECONSTRUCTED, INCLUSION_PROOF_VALID,
 *         AGGREGATED_INTERPRETATION_UNIQUE
 *
 * Follows settlement.aggregated.xrpl/1 section 13 validation procedure.
 */
export function verifySettlement(
  proof: IndependenceProof,
  material: SettlementMaterial | null,
  capacityEvidence: CapacityEvidence | null,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  // Step 1 — Validate profile selection
  if (proof.settlement.profile_id !== REQUIRED_PROFILE) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "REJECTED",
      `settlement_profile_id must be "${REQUIRED_PROFILE}", got "${proof.settlement.profile_id}"`
    );
    return;
  }

  // Every finality witness names the profile's substrate. A witness of another
  // substrate is not one the rules domain admits.
  for (const w of proof.settlement.finality_proofs) {
    if (w.substrate !== REQUIRED_SUBSTRATE) {
      builder.fail(
        "SETTLEMENT_REF_VALID",
        "REJECTED",
        `finality witness substrate "${w.substrate}" is not "${REQUIRED_SUBSTRATE}", the substrate of ${REQUIRED_PROFILE}`
      );
      return;
    }
  }

  // Settlement material presence
  if (!material) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "INCOMPLETE",
      "settlement_material is absent"
    );
    builder.addMissingArtifact("settlement_material");
    return;
  }

  // Profile coherence in material
  if (material.settlement_profile_id !== REQUIRED_PROFILE) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "REJECTED",
      `settlement_material.settlement_profile_id must be "${REQUIRED_PROFILE}", got "${material.settlement_profile_id}"`
    );
    return;
  }

  // Step 2 — settlement reference coherence
  if (proof.settlement_ref !== proof.settlement.ref) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "REJECTED",
      `settlement_ref mismatch: top-level="${proof.settlement_ref}" vs settlement.ref="${proof.settlement.ref}"`
    );
    return;
  }

  // Step 3 — Settlement action shape
  const action = material.settlement_action;
  if (!action) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "INCOMPLETE",
      "settlement_action is absent"
    );
    builder.addMissingArtifact("settlement_action");
    return;
  }

  // chain_id validation per rules-domain/1
  if (action.chain_id !== config.xrpl_chain_id) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "REJECTED",
      `settlement_action.chain_id="${action.chain_id}" does not match required="${config.xrpl_chain_id}"`
    );
    return;
  }

  // XRPL has no sub-position inside a transaction: action_ordinal is always "0"
  // (settlement.aggregated.xrpl/1 §8.1). Checked on its own, not only through the
  // settlement_ref binding, so material whose ref and action agree on another
  // value is still rejected.
  if (action.action_ordinal !== "0") {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "INDEPENDENT_INVALID",
      `settlement_action.action_ordinal="${action.action_ordinal}" must be "0" under this profile`
    );
    return;
  }

  // The settlement destroys supply by paying the MPT back to its own issuer;
  // `contract` names the ISSUANCE (XRPL has no contract accounts) and `name` is
  // the transaction type. Paying the MPT back to its own issuer is what destroys
  // supply: there is no sink account to validate.

  // The settlement MUST debit the aggregate settlement account, never an issuer's
  // own. This is what keeps the ledger from revealing WHICH issuer certified:
  // every settlement in a window comes from the same account, so an observer sees
  // one aggregate burn and cannot attribute it.
  //
  // Checked OFFLINE against the account the rules domain publishes — which is the
  // strongest form available without the ledger, and catches material that
  // declares a foreign account. An online verifier must additionally confirm the
  // real transaction's sender matches, since material can declare anything.
  //
  // An EMPTY configured account is not "no constraint" — it is a configuration
  // that cannot express one, and accepting under it would admit a settlement
  // debited from an issuer's own account. That is the exact thing this check
  // exists to prevent, so it FAILS rather than skipping.
  //
  // A placeholder `system_root_fingerprint` or `xrpl_mpt_issuance_id` (a
  // deployment whose keys do not exist yet) fails closed by never matching real
  // material; an unset account has to be rejected explicitly, because an empty
  // string silently compares as "anything goes".
  if (config.xrpl_settlement_account === "") {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      "no settlement account is configured for this rules domain, so the " +
        "settlement's originating account cannot be checked. Verification fails " +
        "closed rather than accepting a settlement debited from anywhere."
    );
    return;
  }
  if (action.from !== config.xrpl_settlement_account) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `settlement_action.from="${action.from}" is not the aggregate settlement ` +
        `account="${config.xrpl_settlement_account}"`
    );
    return;
  }

  if (action.contract !== config.xrpl_mpt_issuance_id) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `settlement_action.contract="${action.contract}" does not match required="${config.xrpl_mpt_issuance_id}"`
    );
    return;
  }
  if (action.name !== config.xrpl_action_name) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `settlement_action.name="${action.name}" does not match required="${config.xrpl_action_name}"`
    );
    return;
  }

  // Parse the action quantity as a canonical CERT,2 asset (strictly positive,
  // exactly 2 decimals, symbol "CERT") — not a loose suffix match. The numeric
  // portion is reused below in CAPACITY_BINDING_VALID against the ccp, over the
  // SAME canonical bytes every conforming verifier compares.
  const parsedQty = parseCert2Quantity(action.quantity, config.xrpl_token_symbol);
  if ("error" in parsedQty) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      parsedQty.error
    );
    return;
  }
  const actionQty = parsedQty.numeric;

  builder.pass("SETTLEMENT_REF_VALID");

  // Step 4 — Batch binding memo
  // settlement-material/1 §9: one authorization-bridge per distinct resolved authorization in
  // the leaf. Require at least one; the batch_binding_preimage is batch-level, so
  // every entry MUST carry the identical one (the memo binds the whole batch).
  const bridges = material.authorization_bridge_proofs;
  if (!Array.isArray(bridges) || bridges.length === 0) {
    builder.fail(
      "CAPACITY_NOT_RECONSTRUCTED",
      "INCOMPLETE",
      "authorization_bridge_proofs is absent or empty"
    );
    builder.addMissingArtifact("authorization_bridge_proofs");
    return;
  }

  const bbp = bridges[0].batch_binding_preimage;
  if (!bbp) {
    builder.fail(
      "CAPACITY_NOT_RECONSTRUCTED",
      "INCOMPLETE",
      "batch_binding_preimage is absent"
    );
    builder.addMissingArtifact("batch_binding_preimage");
    return;
  }

  // Every bridge must agree on the batch-level binding (one memo per batch).
  const bbpJson = JSON.stringify(bbp);
  for (const b of bridges) {
    if (!b.batch_binding_preimage || JSON.stringify(b.batch_binding_preimage) !== bbpJson) {
      builder.fail(
        "CAPACITY_NOT_RECONSTRUCTED",
        "INDEPENDENT_INVALID",
        "authorization_bridge_proofs disagree on batch_binding_preimage (must be one batch-level binding)"
      );
      return;
    }
  }

  // Build canonical BatchBindingPreimage JSON
  const bbpBytes = canonicalJsonBytes([
    ["v", bbp.v],
    ["system_id", bbp.system_id],
    ["rules_version", bbp.rules_version],
    ["settlement_profile_id", bbp.settlement_profile_id],
    ["batch_id", bbp.batch_id],
    ["window_id", bbp.window_id],
    ["leaf_count", bbp.leaf_count],
    ["total_quantity", bbp.total_quantity],
    ["settlement_root", bbp.settlement_root],
  ]);
  const batchBindingDigest = digestHexBytes(bbpBytes);
  const expectedMemo = `${config.xrpl_memo_prefix}${batchBindingDigest}`;

  if (action.memo !== expectedMemo) {
    builder.fail(
      "CAPACITY_NOT_RECONSTRUCTED",
      "INDEPENDENT_INVALID",
      `Batch binding memo mismatch: expected="${expectedMemo}", got="${action.memo}"`
    );
    return;
  }

  // Step 4b — Bind the SIGNED settlement_ref to the settlement material.
  // settlement_ref is part of the proof's signed view, so its segments are
  // authenticated; settlement_action and batch_binding_preimage are NOT signed.
  // Parse the ref (chain_id:trx_id:action_ordinal:batch_id:window_id) and require
  // each segment to equal the corresponding material field, so the material
  // cannot diverge from what the system domain actually signed (e.g. swapping
  // trx_id / action_ordinal in an otherwise-valid package).
  const refSegments = proof.settlement_ref.split(":");
  if (refSegments.length !== 5) {
    builder.fail(
      "SETTLEMENT_REF_VALID",
      "REJECTED",
      `settlement_ref must have 5 colon-separated segments (chain_id:trx_id:action_ordinal:batch_id:window_id), got ${refSegments.length}`
    );
    return;
  }
  const [refChainId, refTrxId, refActionOrdinal, refBatchId, refWindowId] = refSegments;
  const refBindings: Array<[string, string, string]> = [
    ["chain_id", refChainId, action.chain_id],
    ["trx_id", refTrxId, action.trx_id],
    ["action_ordinal", refActionOrdinal, action.action_ordinal],
    ["batch_id", refBatchId, bbp.batch_id],
    ["window_id", refWindowId, bbp.window_id],
  ];
  for (const [field, fromRef, fromMaterial] of refBindings) {
    if (fromRef !== fromMaterial) {
      builder.fail(
        "SETTLEMENT_REF_VALID",
        "INDEPENDENT_INVALID",
        `signed settlement_ref ${field}="${fromRef}" does not match settlement material "${fromMaterial}"`
      );
      return;
    }
  }

  // Step 5 — Settlement root — recompute from leaf. The leaf=subtree leaf anchors
  // to `subtree_root`, carried in `submission_assignment_proof`.
  const assignment = material.submission_assignment_proof;
  if (!assignment || !assignment.leaf_preimage) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "INCOMPLETE",
      "submission_assignment_proof or leaf_preimage is absent"
    );
    builder.addMissingArtifact("submission_assignment_proof");
    return;
  }

  const lp = assignment.leaf_preimage;
  // The leaf-bound value the proof anchors and the assignment carries.
  const proofLeafValue = proof.subtree_root;
  const leafBoundValue = lp.subtree_root;
  const assignmentBoundValue = assignment.subtree_root;

  if (leafBoundValue === undefined) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "INCOMPLETE",
      "leaf_preimage.subtree_root is absent"
    );
    return;
  }

  // Build canonical LeafPreimage JSON in canonical field order.
  const leafBytes = canonicalJsonBytes([
    ["v", lp.v],
    ["system_id", lp.system_id],
    ["rules_version", lp.rules_version],
    ["settlement_profile_id", lp.settlement_profile_id],
    ["batch_id", lp.batch_id],
    ["leaf_index", lp.leaf_index],
    ["subtree_root", leafBoundValue],
    ["cost_commitment", lp.cost_commitment],
    ["consumed_quantity", lp.consumed_quantity],
  ]);
  const computedLeafHash = computeLeafHash(leafBytes);
  const bap = assignment;

  // Verify leaf hash matches declared
  if (bap.leaf_hash !== computedLeafHash) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "INDEPENDENT_INVALID",
      `Leaf hash mismatch: computed="${computedLeafHash}", declared="${bap.leaf_hash}"`
    );
    return;
  }

  // Verify inclusion proof. The tree width is the anchored leaf_count (the
  // batch_binding_preimage is bound by the memo); proof.batch.size is outside the
  // proof's signed view and is accepted only when it repeats that value.
  const canonicalUint = /^(0|[1-9][0-9]{0,8})$/;
  const leafIndex = canonicalUint.test(bap.leaf_index) ? Number(bap.leaf_index) : NaN;
  const treeSize = canonicalUint.test(bbp.leaf_count) ? Number(bbp.leaf_count) : NaN;

  if (isNaN(leafIndex) || isNaN(treeSize) || treeSize <= 0) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "REJECTED",
      `Invalid leaf_index=${bap.leaf_index} or leaf_count=${bbp.leaf_count}`
    );
    return;
  }
  if (proof.batch.size !== bbp.leaf_count || leafIndex >= treeSize) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "INDEPENDENT_INVALID",
      `batch.size=${proof.batch.size} and leaf_index=${bap.leaf_index} must fit the anchored leaf_count=${bbp.leaf_count}`
    );
    return;
  }

  const inclusionValid = verifyInclusionProof(
    computedLeafHash,
    leafIndex,
    bap.sibling_hashes,
    proof.batch.root,
    treeSize
  );

  if (!inclusionValid) {
    builder.fail(
      "INCLUSION_PROOF_VALID",
      "INDEPENDENT_INVALID",
      "Inclusion proof does not verify: computed root does not match batch.root"
    );
    return;
  }
  builder.pass("INCLUSION_PROOF_VALID");

  // Settlement root consistency. The coherence is three-way (settlement.binding/1
  // §6; independence.proof/1 §10.13.1), so material without a batch_manifest cannot
  // establish it: fail closed as incomplete instead of dereferencing nothing.
  const manifest = material.batch_manifest;
  if (manifest === undefined || manifest === null) {
    builder.fail(
      "AGGREGATED_INTERPRETATION_UNIQUE",
      "INCOMPLETE",
      "batch_manifest is absent"
    );
    builder.addMissingArtifact("batch_manifest");
    return;
  }
  if (
    manifest.settlement_root !== proof.batch.root ||
    bbp.settlement_root !== proof.batch.root
  ) {
    builder.fail(
      "AGGREGATED_INTERPRETATION_UNIQUE",
      "INDEPENDENT_INVALID",
      "settlement_root is not consistent across batch_manifest, batch_binding_preimage, and proof.batch.root"
    );
    return;
  }

  // Step 6 — Leaf assignment: the leaf-bound value (subtree_root) must be consistent
  // across the assignment proof, the leaf preimage, and the proof anchor.
  if (assignmentBoundValue !== proofLeafValue) {
    builder.fail(
      "AGGREGATED_INTERPRETATION_UNIQUE",
      "INDEPENDENT_INVALID",
      `assignment_proof.subtree_root="${assignmentBoundValue}" does not match proof="${proofLeafValue}"`
    );
    return;
  }
  if (leafBoundValue !== proofLeafValue) {
    builder.fail(
      "AGGREGATED_INTERPRETATION_UNIQUE",
      "INDEPENDENT_INVALID",
      `leaf_preimage.subtree_root="${leafBoundValue}" does not match proof="${proofLeafValue}"`
    );
    return;
  }
  if (bap.leaf_index !== proof.batch.index) {
    builder.fail(
      "AGGREGATED_INTERPRETATION_UNIQUE",
      "INDEPENDENT_INVALID",
      `leaf_index mismatch: bap="${bap.leaf_index}" vs batch.index="${proof.batch.index}"`
    );
    return;
  }
  builder.pass("AGGREGATED_INTERPRETATION_UNIQUE");

  // Step 7 — Authorization bridge (zero-data): the bridge must derive from the
  // RESOLVED authorization artifact, not restate a cleartext scope. Under the
  // zero-data profile the resolved authorization IS the system-domain Level-1
  // authorization the capacity evidence carries and capacity-binding re-verifies.
  // So `resolved_authorization_digest` MUST equal SHA3-256 of that evidence's
  // `level1_binding` signing bytes — binding the settlement to the exact
  // authorization the evidence proved, without any correlating issuer_scope.
  if (!capacityEvidence) {
    builder.fail(
      "CAPACITY_NOT_RECONSTRUCTED",
      "INCOMPLETE",
      "no capacity evidence to anchor the authorization bridge to"
    );
    builder.addMissingArtifact("capacity_evidence");
    return;
  }
  const expectedAuthDigest = digestHexBytes(
    level1BindingSigningBytes(
      capacityEvidence.projected_authorization.level1_binding
    )
  );
  // settlement-material/1 §9: select the bridge for the authorization THIS evidence proves.
  // A leaf may carry commitments under different Level-1 authorizations; the
  // verdict for this commitment must reconstruct ITS authorization, not the
  // leaf's first one. Require exactly the matching bridge to be present.
  const matchingBridge = bridges.find(
    (b) => b.resolved_authorization_digest === expectedAuthDigest
  );
  if (!matchingBridge) {
    builder.fail(
      "CAPACITY_NOT_RECONSTRUCTED",
      "INDEPENDENT_INVALID",
      `no authorization_bridge_proof derives from this evidence's resolved ` +
        `authorization: SHA3(level1_binding)="${expectedAuthDigest}" not found among ` +
        `${bridges.length} bridge(s)`
    );
    return;
  }
  builder.pass("CAPACITY_NOT_RECONSTRUCTED");

  // Step 8 — Capacity consumption
  const ccp = material.capacity_consumption_proof;
  if (!ccp) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INCOMPLETE",
      "capacity_consumption_proof is absent"
    );
    builder.addMissingArtifact("capacity_consumption_proof");
    return;
  }

  // `actionQty` is the canonical numeric portion validated by
  // `parseCert2Quantity` above ("10.00 CERT" -> "10.00").
  if (ccp.total_quantity !== actionQty) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `total_quantity mismatch: ccp="${ccp.total_quantity}" vs action="${actionQty}"`
    );
    return;
  }
  // The quantity the batch must have burned is the one ANCHORED on-chain: the
  // `total_quantity` of `batch_binding_preimage`, whose digest the memo check of
  // step 4 has already bound to the settlement transaction (settlement.binding/1
  // §5). `batch_manifest` is unsigned, unanchored material: its copy of the total
  // is only accepted when it repeats the anchored value, and it is never the
  // reference. Comparing against it instead would let material anchor one total,
  // burn a smaller one, and restate the manifest to match the burn.
  if (ccp.total_quantity !== bbp.total_quantity) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `total_quantity mismatch: burned ccp="${ccp.total_quantity}" vs anchored ` +
        `batch_binding_preimage="${bbp.total_quantity}"`
    );
    return;
  }
  // Every field `batch_manifest` restates from `batch_binding_preimage` must
  // repeat the anchored value (settlement.aggregated.xrpl/1 §10.1;
  // settlement.binding/1 §6). The memo anchors the preimage; nothing anchors or
  // signs the manifest, so its copies are accepted only when they agree and are
  // never the reference. The signed settlement_ref (step 4b) binds the
  // PREIMAGE's batch_id and window_id, not the manifest's. `manifest` is present
  // here: its absence failed closed at the settlement root consistency check.
  for (const field of MANIFEST_ANCHORED_FIELDS) {
    if (manifest[field] !== bbp[field]) {
      builder.fail(
        "CAPACITY_BINDING_VALID",
        "INDEPENDENT_INVALID",
        `${field} mismatch: batch_manifest="${manifest[field]}" vs anchored ` +
          `batch_binding_preimage="${bbp[field]}"`
      );
      return;
    }
  }
  if (ccp.leaf_quantity !== lp.consumed_quantity) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `leaf_quantity mismatch: ccp="${ccp.leaf_quantity}" vs leaf="${lp.consumed_quantity}"`
    );
    return;
  }
  // No `sink_account`: the payment returns the MPT to its issuance, which
  // destroys it. There is no destination to name.
  if (ccp.token_contract !== config.xrpl_mpt_issuance_id) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `token_contract mismatch: ccp="${ccp.token_contract}" vs config="${config.xrpl_mpt_issuance_id}"`
    );
    return;
  }
  if (ccp.token_symbol !== config.xrpl_token_symbol) {
    builder.fail(
      "CAPACITY_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `token_symbol mismatch: ccp="${ccp.token_symbol}" vs config="${config.xrpl_token_symbol}"`
    );
    return;
  }
  builder.pass("CAPACITY_BINDING_VALID");

  // Step 9 — Finality
  const fp = material.finality_proof;
  if (!fp) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "INCOMPLETE",
      "finality_proof is absent"
    );
    builder.addMissingArtifact("finality_proof");
    return;
  }

  // Canonical non-negative decimal only (settlement.aggregated.xrpl/1 §11.3):
  // parseInt would accept "12abc", "+5" or "007" and evaluate a value the
  // material never stated.
  const canonical = (s: unknown): s is string =>
    typeof s === "string" && /^(0|[1-9][0-9]*)$/.test(s);
  const blockNum = canonical(fp.block_num) ? Number(fp.block_num) : NaN;
  const libNum = canonical(fp.last_irreversible_block_num)
    ? Number(fp.last_irreversible_block_num)
    : NaN;

  if (isNaN(blockNum) || isNaN(libNum)) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "REJECTED",
      `Invalid block_num="${fp.block_num}" or last_irreversible_block_num="${fp.last_irreversible_block_num}"`
    );
    return;
  }

  if (libNum < blockNum) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "INDEPENDENT_INVALID",
      `Insufficient finality: last_irreversible_block_num=${libNum} < block_num=${blockNum}`
    );
    return;
  }

  if (!fp.block_id || fp.block_id.length === 0) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "REJECTED",
      "finality_proof.block_id is missing or empty"
    );
    return;
  }
  if (
    !fp.last_irreversible_block_id ||
    fp.last_irreversible_block_id.length === 0
  ) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "REJECTED",
      "finality_proof.last_irreversible_block_id is missing or empty"
    );
    return;
  }

  // Check confirmation_level across the finality witnesses (a list; ALL present
  // witnesses must be irreversible).
  const witnesses = proof.settlement.finality_proofs;
  if (!Array.isArray(witnesses) || witnesses.length === 0) {
    builder.fail(
      "FINALITY_SUFFICIENT",
      "REJECTED",
      "settlement.finality_proofs is missing or empty"
    );
    return;
  }
  for (const w of witnesses) {
    if (w.confirmation_level !== "irreversible") {
      builder.fail(
        "FINALITY_SUFFICIENT",
        "INDEPENDENT_INVALID",
        `finality witness (substrate="${w.substrate}") confirmation_level="${w.confirmation_level}" is not "irreversible"`
      );
      return;
    }
    // The witness is a projection of the settlement material, which is
    // authoritative (independence.proof/1 §10.6): a witness naming another
    // ledger or another close time than the material is an incoherent proof.
    if (w.block_height !== fp.block_num || w.timestamp !== fp.block_timestamp) {
      builder.fail(
        "FINALITY_SUFFICIENT",
        "REJECTED",
        `finality witness (block_height="${w.block_height}", timestamp="${w.timestamp}") ` +
          `does not match the settlement material (block_num="${fp.block_num}", ` +
          `block_timestamp="${fp.block_timestamp}")`
      );
      return;
    }
  }

  builder.pass("FINALITY_SUFFICIENT");

  // Commitment TTL: the signed expiry window MUST match the rules-domain TTL
  // (rules/2026-01), so an issuer cannot inflate its own window (e.g. emit
  // issued_at=today, expires_at=2100). expires_at MUST equal issued_at +
  // commitment_ttl_seconds exactly. Both timestamps are inside the signed
  // projected_commitment; the TTL comes from public rules. Fail-closed:
  // without this the block_timestamp ≤ expires_at check below is toothless
  // (a forged far-future expires_at would always pass it).
  if (capacityEvidence) {
    const issuedAt = parseCommitmentInstant(
      capacityEvidence.projected_commitment.issued_at
    );
    const expiresAtTtl = parseCommitmentInstant(
      capacityEvidence.projected_commitment.expires_at
    );
    if (issuedAt === null || expiresAtTtl === null) {
      builder.fail(
        "COMMITMENT_TTL_VALID",
        "REJECTED",
        `issued_at="${capacityEvidence.projected_commitment.issued_at}" or ` +
          `expires_at="${capacityEvidence.projected_commitment.expires_at}" is not ` +
          `RFC 3339 UTC with whole seconds`
      );
      return;
    }
    const expectedExpires = issuedAt + config.commitment_ttl_seconds * 1000;
    if (expiresAtTtl !== expectedExpires) {
      builder.fail(
        "COMMITMENT_TTL_VALID",
        "INDEPENDENT_INVALID",
        `expires_at=${capacityEvidence.projected_commitment.expires_at} does not equal ` +
          `issued_at + commitment_ttl_seconds (${config.commitment_ttl_seconds}s); ` +
          `the issuer's window does not match the rules-domain TTL`
      );
      return;
    }
    builder.pass("COMMITMENT_TTL_VALID");
  }

  // No-retroactivity, reanchored to the substrate: the capacity
  // consumption's irreversible block time MUST NOT be after the capacity
  // commitment's `expires_at` (settlement.binding/1 §9). The verdict's "when"
  // is the block, NOT CERTCRYPT's clock: no CERTCRYPT-sealed timestamp takes
  // part in this check.
  if (capacityEvidence) {
    const blockTs = Date.parse(fp.block_timestamp);
    const expiresAt = parseCommitmentInstant(
      capacityEvidence.projected_commitment.expires_at
    );
    if (isNaN(blockTs) || expiresAt === null) {
      builder.fail(
        "SETTLEMENT_NOT_RETROACTIVE",
        "REJECTED",
        `unparseable block_timestamp="${fp.block_timestamp}" or expires_at="${capacityEvidence.projected_commitment.expires_at}"`
      );
      return;
    }
    if (blockTs > expiresAt) {
      builder.fail(
        "SETTLEMENT_NOT_RETROACTIVE",
        "INDEPENDENT_INVALID",
        `settlement block_timestamp=${fp.block_timestamp} is after the capacity commitment expires_at=${capacityEvidence.projected_commitment.expires_at}`
      );
      return;
    }
    builder.pass("SETTLEMENT_NOT_RETROACTIVE");
  }

  // Coherence material
  const cm = material.coherence_material;
  if (cm) {
    if (cm.system_id !== proof.system_id) {
      builder.fail(
        "AGGREGATED_INTERPRETATION_UNIQUE",
        "INDEPENDENT_INVALID",
        `coherence_material.system_id="${cm.system_id}" does not match proof="${proof.system_id}"`
      );
      return;
    }
    if (cm.rules_version !== proof.rules_version) {
      builder.fail(
        "AGGREGATED_INTERPRETATION_UNIQUE",
        "INDEPENDENT_INVALID",
        `coherence_material.rules_version="${cm.rules_version}" does not match proof="${proof.rules_version}"`
      );
      return;
    }
    if (cm.settlement_profile_id !== proof.settlement.profile_id) {
      builder.fail(
        "AGGREGATED_INTERPRETATION_UNIQUE",
        "INDEPENDENT_INVALID",
        `coherence_material.settlement_profile_id="${cm.settlement_profile_id}" does not match proof="${proof.settlement.profile_id}"`
      );
      return;
    }
  }
}
