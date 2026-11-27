# Check Catalog

This document maps the check identifiers of `verifier-toolkit/1` §9.7, which are normative, to this implementation: where each is decided and what fixtures pin it. Where this table and the specification differ, the specification governs.

It should be used as the bridge between:

- public rule
- expected verifier behavior
- fixture coverage
- implementation path

## Failure Classifications

- `REJECTED`: malformed, ambiguous, heuristically recoverable only, parser-dependent, or otherwise non-conformant input
- `INCOMPLETE`: required artifact or required proof material missing
- `UNSUPPORTED`: version, model, or capability not implemented
- `ISSUED_INVALID`: `Issued` path completed and failed (also a material mismatch, §8.5.2)
- `INDEPENDENT_INVALID`: `Independent` path completed and failed

The result code is the highest classification among the failed checks, in the order `REJECTED` > `INCOMPLETE` > `UNSUPPORTED` > `ISSUED_INVALID` > `INDEPENDENT_INVALID` (`verifier-toolkit/1` §9.5).

## Check Inventory

| check_id | target | purpose | required inputs | failure classification | public rule source |
|---|---|---|---|---|---|
| `TARGET_AUTO_RESOLUTION_VALID` | `Issued`, `Independent` | Resolve `auto` deterministically without hiding an incomplete `Independent` path behind apparent `Issued` success. | request metadata and full artifact context | `INCOMPLETE` | `verifier-toolkit/1` §11.4 |
| `INPUT_TARGET_SUPPORTED` | `Issued`, `Independent` | Ensure the requested verification target is one of the supported normative routes. | request metadata | `UNSUPPORTED` | `verifier-toolkit/1` §11.4 |
| `INPUT_MODE_SUPPORTED` | `Issued`, `Independent` | Ensure the input mode is `package` or `artifact_set`. | request metadata | `UNSUPPORTED` | `verifier-toolkit/1` §6 |
| `INPUT_COMBINATION_VALID` | `Issued`, `Independent` | Reject contradictory or ambiguous input combinations. | request metadata | `REJECTED` | `verifier-toolkit/1` §6, §7.2 |
| `PACKAGE_STRUCTURE_VALID` | `Issued`, `Independent` | Validate package structure when `verification_package` is used. | `verification_package` | `REJECTED` | `verifier-toolkit/1` §11.1–§11.2; `verification-package/1` §9.4 |
| `PACKAGE_CONTEXT_COHERENT` | `Issued`, `Independent` | Reject mixed-package substitution and cross-context splicing. | package artifacts | `REJECTED` | `verifier-toolkit/1` §11.2, §13; `verification-package/1` §13 |
| `BASE_CERTIFICATE_PRESENT` | `Issued`, `Independent` | Require `base_certificate` for all conforming verification paths. | `base_certificate` | `INCOMPLETE` | `verifier-toolkit/1` §8.1 |
| `BASE_CERTIFICATE_STRUCTURE_VALID` | `Issued`, `Independent` | Validate base certificate structure. | `base_certificate` | `REJECTED`, `UNSUPPORTED`, `INCOMPLETE` | `verifier-toolkit/1` §11.1; `CCSP/1` §6–§9 |
| `BASE_CERTIFICATE_AUTHENTIC` | `Issued`, `Independent` | Validate base certificate authenticity under applicable public rules: the composite signature (classical component AND ML-DSA-65), which is the only signature verdict. | `base_certificate` | `ISSUED_INVALID`, `REJECTED`, `UNSUPPORTED` | `verifier-toolkit/1` §11.1; `CCSP/1` §7.4 |
| `ORIGINAL_MATERIAL_COMPARISON_VALID` | `Issued`, `Independent` | Validate original material only when the selected path requires it. | original material and bound certificate inputs | `ISSUED_INVALID`, `REJECTED`, `INCOMPLETE`, `UNSUPPORTED` | `verifier-toolkit/1` §8.5, §15 |
| `PROOF_PRESENT` | `Independent` | Require `independence_proof` for `Independent`. | `independence_proof` | `INCOMPLETE` | `verifier-toolkit/1` §8.2 |
| `PROOF_VERSION_SUPPORTED` | `Independent` | Ensure the proof version is supported. | `independence_proof` | `UNSUPPORTED` | `verifier-toolkit/1` §12.2 step 1 |
| `PROOF_STRUCTURE_VALID` | `Independent` | Validate proof structure and minimum logical fields. | `independence_proof` | `REJECTED` | `verifier-toolkit/1` §12.1, §12.2 step 1 |
| `PROOF_SIGNATURE_VALID` | `Independent` | Verify the composite signature (ECDSA-P256-SHA3-256 AND ML-DSA-65) over the signed proof view (independence.proof/1 §10.13.1, `anti_replay` and `node_attestation` included) against the system-domain Level-1 composite capacity key carried by the `system_foundation`. MANDATORY under every rules domain: absent signature or key → `INCOMPLETE`, unavailable ML-DSA-65 runtime → `UNSUPPORTED`, malformed → `REJECTED`, not verifying → `INDEPENDENT_INVALID`. Once it passes, the node attestation is authentic and is reported as `attested_node` on `INDEPENDENT_VALID`. | `independence_proof` and system-domain key material | `INCOMPLETE`, `UNSUPPORTED`, `REJECTED`, `INDEPENDENT_INVALID` | `verifier-toolkit/1` §12.2 step 3; `independence.proof/1` §10.13, §10.15 |
| `RULES_DOMAIN_EXACT` | `Independent` | Select one exact applicable rules domain without fallback or parser discretion. | proof and rule artifacts | `REJECTED`, `UNSUPPORTED` | `verifier-toolkit/1` §7.2, §12.2 step 2; `rules-domain/1` |
| `RULES_CORPUS_COMMITMENT_PRESENT` | `Independent` | Require the certified corpus commitment of the selected rules version in the configuration. | configuration | `REJECTED` | `rules-domain/1` §13.3.1 |
| `SYSTEM_DOMAIN_EXACT` | `Independent` | Validate exact CERTCRYPT system-domain attribution. | proof and system-domain artifacts | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §12.2 step 3; `system-domain/1` |
| `SYSTEM_ROOT_BINDING_VALID` | `Independent` | Require root-material binding, not bare `system_id`. | proof and system-domain artifacts | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §12.2 step 3; `system-domain/1` |
| `LEAF_BINDING_VALID` | `Independent` | Validate the leaf/subtree hybrid binding: the certificate's commitment binds to the proof's subtree root. | proof and certificate commitment material | `INDEPENDENT_INVALID`, `INCOMPLETE`, `REJECTED` | `verifier-toolkit/1` §11.2.1, §12.2 step 4; `independence.proof/1` §7.10, §12.4 |
| `SETTLEMENT_REF_VALID` | `Independent` | Validate the claimed settlement reference or settlement-derived proof material. | settlement artifacts | `INDEPENDENT_INVALID`, `INCOMPLETE`, `REJECTED` | `verifier-toolkit/1` §12.2 step 7 |
| `FINALITY_SUFFICIENT` | `Independent` | Validate sufficient finality under the applicable public rules. | settlement artifacts and rules material | `INDEPENDENT_INVALID`, `INCOMPLETE`, `REJECTED` | `verifier-toolkit/1` §12.2 step 8; `independence.proof/1` §10.6 |
| `SETTLEMENT_NOT_RETROACTIVE` | `Independent` | Reject a settlement whose finality precedes the issuance it is claimed to settle. | settlement artifacts and issuance context | `INDEPENDENT_INVALID`, `REJECTED` | `verifier-toolkit/1` §9.4 class 1 |
| `COMMITMENT_TTL_VALID` | `Independent` | Require the commitment to fall within the TTL the applicable rules allow (`commitment_ttl_seconds`). | settlement artifacts and rules material | `INDEPENDENT_INVALID`, `REJECTED` | `verifier-toolkit/1` §9.7 |
| `CAPACITY_BINDING_VALID` | `Independent` | Validate inseparable binding between settlement context and `capacity_ref`, including that the burned quantity equals the batch total anchored by the batch binding memo (`batch_binding_preimage.total_quantity`), and that every member `batch_manifest` shares with `batch_binding_preimage` repeats the anchored value. | settlement artifacts and capacity-bound proof material | `INDEPENDENT_INVALID`, `INCOMPLETE` | `verifier-toolkit/1` §8.2, §12.2; `settlement.aggregated.xrpl/1` §10.1; `settlement.binding/1` §6 |
| `CAPACITY_NOT_RECONSTRUCTED` | `Independent` | Reject locally invented, approximated, or detached capacity evidence. | settlement artifacts and capacity-bound proof material | `INDEPENDENT_INVALID`, `INCOMPLETE` | `verifier-toolkit/1` §8.2, §12.2 |
| `CAPACITY_EVIDENCE_VALID` | `Independent` | Recompute the zero-data capacity-evidence digest and require it to equal the digest bound in the proof. | capacity evidence and capacity-bound proof material | `INDEPENDENT_INVALID`, `INCOMPLETE` | `independence.proof/1` §12.5; `capacity.evidence/1` |
| `EFFECTIVE_UNITS_BINDING_VALID` | `Independent` | Validate the binding between the declared effective units and the settled capacity. | capacity-bound proof and settlement material | `INDEPENDENT_INVALID`, `REJECTED` | `verifier-toolkit/1` §12.2 step 10 |
| `INCLUSION_PROOF_VALID` | `Independent` | Validate inclusion proof when settlement mode is aggregated. | inclusion proof and aggregated settlement material | `INDEPENDENT_INVALID`, `INCOMPLETE`, `REJECTED` | `verifier-toolkit/1` §12.2 steps 5–6 |
| `AGGREGATED_INTERPRETATION_UNIQUE` | `Independent` | Reject aggregated settlement when more than one plausible bundle assignment exists, including when `settlement_root` is not identical across `batch_manifest`, `batch_binding_preimage` and `proof.batch.root`; material without `batch_manifest` cannot establish that coherence and is `INCOMPLETE`. | aggregated settlement material | `INDEPENDENT_INVALID`, `INCOMPLETE` | `verifier-toolkit/1` §13, §14; `settlement.binding/1` §6 |
| `ISSUANCE_PARTICIPATION_VALID` | `Independent` | Validate issuance-time participation under the applicable public rules. | proof and supporting artifacts | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §9.4 classes 1 and 9 |
| `NON_REPLAY_VALID` | `Independent` | Recompute `anti_replay` (`nonce`, `derivation`) from the proof's `settlement_ref` and `subtree_root` and require exact equality; reject replay or non-unique independence context. | proof and supporting artifacts | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §12.2 step 9; `independence.proof/1` §10.9, §12.9 |
| `ANTI_SPLICING_VALID` | `Independent` | Reject individually valid artifacts that do not belong to one exact verification context. | full proof context | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §13 |
| `CLONE_OR_FORK_REJECTED` | `Independent` | Reject clone or fork proof contexts that mimic CERTCRYPT shapes without valid domain attribution. | proof and system-domain artifacts | `INDEPENDENT_INVALID` | `verifier-toolkit/1` §13; `system-domain/1` |
| `FOUNDATION_PROFILE_VALID` | `Foundation` | Validate the `system-foundation/1` profile shape. | `system_foundation` | `REJECTED` | `system-foundation/1` |
| `FOUNDATION_SYSTEM_ID_VALID` | `Foundation` | Validate the foundation `system_id`. | `system_foundation` | `REJECTED` | `system-foundation/1` |
| `FOUNDATION_FINGERPRINT_RECOMPUTED` | `Foundation` | Recompute the bootstrap fingerprint and require an exact match. | `system_foundation` | `REJECTED` | `system-foundation/1` |
| `FOUNDATION_SIGNATURE_VALID` | `Foundation` | Verify the foundation statement's `statement_signatures` against the bootstrap entry's quorum: at least `quorum.k` distinct bootstrap members whose composite signatures (`certcrypt-composite-p256-mldsa65-v1`: ECDSA-P256-SHA3-256 AND ML-DSA-65, both required) verify over `SHA3-256(UTF-8(JCS(statement payload)))`. The payload includes the `system_domain_capacity_key_*` members, which must decode to valid component keys, so a capacity-key swap under intact signatures fails here. Non-members and failing signatures never count, and a member signing twice counts once. A bootstrap entry declaring any other algorithm is rejected earlier, under `FOUNDATION_FINGERPRINT_RECOMPUTED`. | `system_foundation` | `REJECTED` | `system-foundation/1`; `system-manifest/1` |
| `FOUNDATION_BOOTSTRAP_MATCHES_RULES` | `Foundation` | Require the registered bootstrap statement: root fingerprint, statement id and payload digest. | `system_foundation` and rules material | `REJECTED` | `system-foundation/1` |
| `FOUNDATION_SUCCESSOR_QUORUM_VALID` | `Foundation` | When successor-binding observations accompany the foundation, require each one to name the embedded bootstrap entry as predecessor, to carry a closed §9 successor-binding payload, and to be authorized by at least `quorum.k` distinct bootstrap members whose composite signatures verify over `SHA3-256(UTF-8(JCS(payload)))`. Non-members, failing signatures and repeated signers never count. | `system_foundation` | `REJECTED` | `system-manifest/1` sections 9, 12.3, 13.6 |
| `FOUNDATION_EQUIVOCATION_DETECTED` | `Foundation` | Detect equivocation: two authenticated successor-binding observations over the same predecessor index tuple that authorize different successors. Only observations that passed `FOUNDATION_SUCCESSOR_QUORUM_VALID` are compared. | `system_foundation` | `REJECTED` | `system-manifest/1` section 12.5 |

## The Post-Quantum Component

The ML-DSA-65 (FIPS 204) component is verified **inside**
`BASE_CERTIFICATE_AUTHENTIC`, as one of the two halves of the composite
signature. It is normative: a missing, failing, malformed, or unverifiable
ML-DSA-65 component prevents a `*_VALID` verdict and appears in
`failed_check_ids` under `BASE_CERTIFICATE_AUTHENTIC`.

Its outcome is *additionally* reported in
`additional_verifications.pqc_base_certificate_authentic` for visibility. That
field reports the verdict; it does not carry it.

There is no separate check id for the post-quantum component (verifier-toolkit/1
§9.7).

See [`docs/audit/pqc-normative-runtime.md`](./pqc-normative-runtime.md).

## Coverage Rule

Every check listed above must eventually be mapped to:

- at least one positive fixture when applicable
- at least one negative fixture when applicable
- one implementation path under `core/`

No check may remain purely documentary.
