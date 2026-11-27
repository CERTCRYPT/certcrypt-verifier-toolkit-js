import type { BaseCertificate, SubjectCommitment } from "../types/artifacts.js";
import type { CapacityEvidence } from "../types/capacity-evidence.js";
import type {
  SubjectMaterialMap,
  CollectionMaterial,
  PrehashedMaterial,
  AiDecisionMaterial
} from "../types/artifacts.js";
import type { ResultBuilder } from "../result/builder.js";
import { SUBJECT_COLLECTION } from "../crypto/canonical-subject.js";

/**
 * EFFECTIVE_UNITS_BINDING_VALID — bind the issuer-declared per-subject economic
 * quantity to the subjects actually certified.
 *
 * Normative rule (capacity.commitment/1, submission-set/1):
 * the effective declared units of a leaf MUST EQUAL the sum of the effective
 * declared units of every certified subject bound into that leaf, where
 *   - a `subject.collection/1` subject contributes exactly its `declared_cardinality`, and
 *   - any other subject contributes exactly `1`
 * (the default `1` applies even where the subject carries no cardinality field).
 *
 * This check binds declared effective units to the certified subjects;
 * under-declaration is rejected: a base certificate that certifies N subjects
 * while its capacity evidence declares `declared_effective_units = "1"` fails.
 * No server-side actor can check this under the zero-data profile — the
 * submission-set carries evidence digests, not the base certificate or its subjects. The offline verifier is
 * the only actor holding BOTH the subjects (from the base certificate anchor)
 * AND `declared_effective_units` (from the capacity evidence), so the
 * enforcement lives here and is fail-closed (INDEPENDENT_INVALID on mismatch).
 *
 * Cardinality source. A collection subject carries its `subject.collection/1`
 * descriptor inside the signed anchor (`subjects[i].collection`), so its
 * `declared_cardinality` is normally read from there and the exact sum is known
 * offline, with no original material. Only when the signed subject carries no
 * readable descriptor is a descriptor delivered with the original material used
 * instead. So:
 *   - every subject contributes a known LOWER BOUND of 1 (collections ≥ 1);
 *   - when a collection's `declared_cardinality` resolves (signed descriptor
 *     first, delivered material otherwise), that subject's exact contribution
 *     is used instead of the lower bound.
 * If the exact sum is fully known (no collections, or all collections resolved)
 * we enforce strict equality. If a collection is present but its cardinality is
 * unresolved, we can still enforce the lower bound (an
 * under-declaration below the subject count is always caught), and we defer the
 * exact-equality assertion with an informational diagnostic rather than
 * asserting an equality we cannot compute.
 */
export function verifyEffectiveUnitsBinding(
  baseCertificate: BaseCertificate | null,
  capacityEvidence: CapacityEvidence | null,
  originalMaterial: SubjectMaterialMap | null,
  builder: ResultBuilder
): void {
  // No capacity evidence means there is no declared_effective_units to bind. A null capacityEvidence never reaches
  // INDEPENDENT_VALID anyway — the leaf-binding, settlement, and capacity-binding
  // steps each fail closed (INCOMPLETE) before build() could pass — so not
  // emitting this check here does not weaken the fail-closed posture.
  if (!capacityEvidence) {
    return;
  }

  const subjects = baseCertificate?.payload?.anchor?.subjects;
  if (!Array.isArray(subjects) || subjects.length === 0) {
    builder.fail(
      "EFFECTIVE_UNITS_BINDING_VALID",
      "INDEPENDENT_INVALID",
      "base certificate anchor carries no subjects to bind declared_effective_units to"
    );
    return;
  }

  const declaredStr = capacityEvidence.projected_commitment.declared_effective_units;
  // Canonical unsigned-integer string (submission-set/1: canonical
  // decimal string, never a JSON number).
  if (typeof declaredStr !== "string" || !/^[1-9][0-9]*$/.test(declaredStr)) {
    builder.fail(
      "EFFECTIVE_UNITS_BINDING_VALID",
      "REJECTED",
      `declared_effective_units must be a canonical positive integer string, got ${JSON.stringify(
        declaredStr
      )}`
    );
    return;
  }
  const declared = BigInt(declaredStr);

  // Sum the effective units over the anchor subjects. `lowerBound` is what we
  // can prove without material (each subject ≥ 1). `exact` is the true sum,
  // valid only when `exactKnown` stays true (every collection resolved).
  let lowerBound = 0n;
  let exact = 0n;
  let exactKnown = true;

  for (let i = 0; i < subjects.length; i++) {
    const s = subjects[i];
    if (s?.profile === SUBJECT_COLLECTION) {
      lowerBound += 1n; // a collection contributes ≥ 1
      const card = resolveDeclaredCardinality(s, originalMaterial?.get(i));
      if (card === null) {
        // declared_cardinality not available offline without original material.
        exactKnown = false;
      } else if (card <= 0n) {
        builder.fail(
          "EFFECTIVE_UNITS_BINDING_VALID",
          "REJECTED",
          `subject index ${i}: collection declared_cardinality must be a positive integer`
        );
        return;
      } else {
        exact += card;
      }
    } else {
      // capacity.commitment/1: any non-collection subject contributes
      // exactly 1, even if it carries no cardinality field.
      lowerBound += 1n;
      exact += 1n;
    }
  }

  if (exactKnown) {
    if (exact !== declared) {
      builder.fail(
        "EFFECTIVE_UNITS_BINDING_VALID",
        "INDEPENDENT_INVALID",
        `declared_effective_units="${declaredStr}" does not equal the sum of ` +
          `per-subject effective units (Σ=${exact.toString()} over ${subjects.length} ` +
          `certified subject(s); capacity.commitment/1)`
      );
      return;
    }
    builder.pass("EFFECTIVE_UNITS_BINDING_VALID");
    return;
  }

  // Exact sum is unknown because a collection's declared_cardinality was not
  // supplied (no original material). We can still fail closed when the declared
  // value is below the provable lower bound — the under-declaration attack the
  // check exists to stop is always caught.
  if (declared < lowerBound) {
    builder.fail(
      "EFFECTIVE_UNITS_BINDING_VALID",
      "INDEPENDENT_INVALID",
      `declared_effective_units="${declaredStr}" is below the minimum ` +
        `${lowerBound.toString()} implied by ${subjects.length} certified subject(s) ` +
        `(each subject contributes ≥ 1; capacity.commitment/1)`
    );
    return;
  }
  // Lower bound satisfied but exact equality cannot be asserted offline without
  // the collection material. Pass the lower-bound check; note that exact
  // equality was deferred (parallels the opt-in complete-material plane).
  builder.addDiagnostic(
    "info",
    `EFFECTIVE_UNITS_BINDING_VALID: exact per-subject sum not recomputed — a ` +
      `subject.collection/1 declared_cardinality was not supplied (no original ` +
      `material). Enforced lower bound ${lowerBound.toString()} ≤ declared_effective_units ` +
      `="${declaredStr}"; supply original material to enforce strict equality.`,
    "EFFECTIVE_UNITS_BINDING_VALID"
  );
  builder.pass("EFFECTIVE_UNITS_BINDING_VALID");
}

/**
 * Extract a collection subject's `declared_cardinality` from its signed
 * descriptor or, failing that, from its verifier-local material entry; null when
 * neither carries one.
 * Validates the canonical positive-integer string form (subject.collection/1).
 */
function resolveDeclaredCardinality(
  subject: SubjectCommitment | undefined,
  entry: Uint8Array | CollectionMaterial | PrehashedMaterial | AiDecisionMaterial | undefined
): bigint | null {
  // Preferred source: the descriptor signed inside the subject, which makes the
  // exact sum available offline, with no original material.
  const signed = subject?.collection?.declared_cardinality;
  if (typeof signed === "string" && /^[1-9][0-9]*$/.test(signed)) {
    return BigInt(signed);
  }
  // Otherwise: a descriptor delivered with the original material, if any. A prehashed
  // entry or an AI-decision entry never carries a collection descriptor.
  if (!entry || entry instanceof Uint8Array || "prehashed" in entry || "record" in entry) {
    return null;
  }
  const collection = (entry as CollectionMaterial).collection;
  if (typeof collection !== "object" || collection === null) {
    return null;
  }
  const card = (collection as { declared_cardinality?: unknown }).declared_cardinality;
  if (typeof card !== "string" || !/^[1-9][0-9]*$/.test(card)) {
    return null;
  }
  return BigInt(card);
}
