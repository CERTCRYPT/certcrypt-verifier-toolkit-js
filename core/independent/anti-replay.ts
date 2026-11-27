import type { IndependenceProof } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { deriveAntiReplay } from "./proof-views.js";

/**
 * Verify anti-replay constraints.
 *
 * Check: NON_REPLAY_VALID
 *
 * Per independence.proof/1 §10.9 and §12.9, `anti_replay` is derived from the
 * proof's own `settlement_ref` and `subtree_root`; the verifier recomputes both
 * members and requires exact equality. A value bound to another settlement
 * container or another leaf therefore fails here even when it is well formed
 * and signed. The non-replay property itself also rests on the settlement
 * binding and the inclusion proof, checked in the settlement step.
 */
export function verifyAntiReplay(
  proof: IndependenceProof,
  builder: ResultBuilder
): void {
  const ar = proof.anti_replay;
  if (!ar || !ar.nonce || !ar.derivation) {
    builder.fail(
      "NON_REPLAY_VALID",
      "INDEPENDENT_INVALID",
      "anti_replay.nonce or anti_replay.derivation is missing or empty"
    );
    return;
  }

  const expected = deriveAntiReplay(proof.settlement_ref, proof.subtree_root);
  if (ar.nonce !== expected.nonce || ar.derivation !== expected.derivation) {
    builder.fail(
      "NON_REPLAY_VALID",
      "INDEPENDENT_INVALID",
      "anti_replay is not the derivation from this proof's settlement_ref and subtree_root"
    );
    return;
  }

  builder.pass("NON_REPLAY_VALID");
}
