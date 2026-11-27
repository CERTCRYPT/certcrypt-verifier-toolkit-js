# Conformance Map

This document traces the verifier from public rule to executable evidence.

The fixtures live in the `certcrypt-conformance` repository under
`fixtures/conformance/` and `fixtures/adversarial/`. The harness
(`scripts/run-conformance.ts`, `npm run test:conformance`) resolves them from a
sibling checkout or `CERTCRYPT_CONFORMANCE_DIR`. Each negative fixture breaks
exactly one property; its `expected-result.json` names the failing `check_id`
and the resulting `result_code`.

## Mapping

| mandatory behavior | `check_id` | fixture | expected result code | implementation path |
|---|---|---|---|---|
| deterministic `auto` resolution without semantic downgrade | `TARGET_AUTO_RESOLUTION_VALID` | `adversarial/V021` | `INCOMPLETE` | `core/input/`, `core/result/` |
| reject contradictory input combinations | `INPUT_COMBINATION_VALID` | `adversarial/V015` | `REJECTED` | `core/input/` |
| validate base certificate structure | `BASE_CERTIFICATE_STRUCTURE_VALID` | `adversarial/V012` | `REJECTED` | `core/issued/` |
| validate base certificate authenticity (composite) | `BASE_CERTIFICATE_AUTHENTIC` | `adversarial/S002`, `adversarial/S005` (invalid signature); `adversarial/S003`, `adversarial/S004` (malformed material) | `ISSUED_INVALID`; `REJECTED` | `core/issued/`, `core/crypto/composite.ts` |
| validate proof structure | `PROOF_STRUCTURE_VALID` | `adversarial/V007`, `adversarial/V053` (`proof_id` not the identity-view digest), `adversarial/V054` (`closure_time` absent) | `REJECTED` | `core/independent/proof-structure.ts` |
| mandatory proof signature over the signed view | `PROOF_SIGNATURE_VALID` | `conformance/S006`; `adversarial/S007` (node attestation altered), `adversarial/S008` (unsigned), `adversarial/S009`-`S011` (composite layout: order, `low_s`, extra member) | `INDEPENDENT_VALID`; `INDEPENDENT_INVALID`; `INCOMPLETE`; `REJECTED` | `core/independent/verify-proof-signature.ts` |
| node attestation reported, authenticated by the signature | (all pass) | `conformance/P010` (`attested_node`) | `INDEPENDENT_VALID` | `core/independent/verify-independent.ts`, `core/result/builder.ts` |
| anti_replay recomputed | `NON_REPLAY_VALID` | `adversarial/V055` (derived for another context); an empty `anti_replay` is refused earlier, under `PROOF_STRUCTURE_VALID` (`adversarial/V007`) | `INDEPENDENT_INVALID`; `REJECTED` | `core/independent/anti-replay.ts` |
| exact rules-domain selection | `RULES_DOMAIN_EXACT` | `adversarial/V003` | `REJECTED` | `core/rules/` |
| exact system-domain attribution | `SYSTEM_DOMAIN_EXACT` | `adversarial/V002` | `INDEPENDENT_INVALID` | `core/domain/` |
| root-material binding, not bare `system_id` | `SYSTEM_ROOT_BINDING_VALID` | `adversarial/V019` | `INDEPENDENT_INVALID` | `core/domain/` |
| validate the leaf/subtree hybrid binding | `LEAF_BINDING_VALID` | `adversarial/V001`, `adversarial/V013` | `INDEPENDENT_INVALID` | `core/independent/leaf-binding.ts` |
| validate the settlement reference | `SETTLEMENT_REF_VALID` | `adversarial/V008`, `adversarial/V016`, `adversarial/V017` | `REJECTED` | `core/independent/settlement.ts` |
| sufficient finality | `FINALITY_SUFFICIENT` | `adversarial/V009`, `adversarial/V018`; `adversarial/V056` (finality witness disagrees with the settlement material) | `INDEPENDENT_INVALID`; `REJECTED` | `core/independent/settlement.ts` |
| settlement-bound capacity validation | `CAPACITY_BINDING_VALID` | `adversarial/V006`, `adversarial/V010`, `adversarial/V011`, `adversarial/V026` | `INDEPENDENT_INVALID` | `core/independent/capacity-binding.ts` |
| burned quantity against the anchored batch total, not the unanchored manifest | `CAPACITY_BINDING_VALID` | `adversarial/V043` (burn below the anchored total, manifest restated), `adversarial/V044` (manifest copy diverges) | `INDEPENDENT_INVALID` | `core/independent/settlement.ts` |
| every member the manifest restates from the anchored preimage, never the manifest as reference | `CAPACITY_BINDING_VALID` | `adversarial/V044` (`total_quantity`), `adversarial/V046` (`leaf_count`), `adversarial/V047` (`batch_id`); the other shared members by unit test | `INDEPENDENT_INVALID` | `core/independent/settlement.ts` |
| reject reconstructed/detached capacity evidence | `CAPACITY_NOT_RECONSTRUCTED` | `adversarial/V005` | `INCOMPLETE` | `core/independent/capacity-binding.ts` |
| inclusion proof for aggregated settlement | `INCLUSION_PROOF_VALID` | `adversarial/V024` | `INCOMPLETE` | `core/independent/settlement.ts` |
| unique aggregated interpretation | `AGGREGATED_INTERPRETATION_UNIQUE` | `adversarial/V004`, `adversarial/V025`, `adversarial/V027` | `INDEPENDENT_INVALID` | `core/independent/settlement.ts` |
| settlement-root coherence needs the batch manifest | `AGGREGATED_INTERPRETATION_UNIQUE` | `adversarial/V045` (`batch_manifest` absent) | `INCOMPLETE` | `core/independent/settlement.ts` |
| issuance-time participation | `ISSUANCE_PARTICIPATION_VALID` | `adversarial/V020`, `adversarial/V028` | `INDEPENDENT_INVALID` | `core/independent/issuance-participation.ts` |
| clone/fork rejection | `CLONE_OR_FORK_REJECTED` | `adversarial/V002`, `adversarial/V019` | `INDEPENDENT_INVALID` | `core/domain/`, `core/independent/` |
| foundation profile / fingerprint / signature / registered bootstrap / closed shapes | `FOUNDATION_*` | `adversarial/F002`-`F004`, `F006`-`F018` (positives: `conformance/F001`, `conformance/F005`) | `REJECTED` | `core/foundation/verify-foundation.ts`, `core/verify.ts` |
| positive `Independent` baseline | (all pass) | `conformance/P001`-`P008` | `INDEPENDENT_VALID` | `core/independent/` |
| original material: collection leaves, root and cardinality (§8.5.3) | `ORIGINAL_MATERIAL_COMPARISON_VALID` | `conformance/P007`; `adversarial/V038` (cardinality lie), `adversarial/V039` (tampered leaf), `adversarial/V040` (leaf profile not admitted) | `INDEPENDENT_VALID`; `REJECTED`; `ISSUED_INVALID` | `core/issued/verify-original-material.ts` |
| original material: AI-decision input and output against the record's digests (§8.5.6) | `ORIGINAL_MATERIAL_COMPARISON_VALID` | `conformance/P011`; `adversarial/V057` (output does not match) | `INDEPENDENT_VALID`; `ISSUED_INVALID` | `core/issued/verify-original-material.ts` |
| successor binding authorized by the predecessor quorum | `FOUNDATION_SUCCESSOR_QUORUM_VALID` | `conformance/P009` | `INDEPENDENT_VALID` | `core/foundation/verify-foundation.ts` |
| positive composite authenticity | `BASE_CERTIFICATE_AUTHENTIC` | `conformance/S001`, `conformance/S006` | `INDEPENDENT_VALID` | `core/issued/`, `core/crypto/composite.ts` |
| post-quantum component of the composite (normative) | `BASE_CERTIFICATE_AUTHENTIC` | `conformance/Q001`-`Q002` (dual-signed positives); `adversarial/Q003`, `adversarial/Q005` (broken / mis-domained component) | `INDEPENDENT_VALID`; `ISSUED_INVALID` | `core/crypto/composite.ts`, `core/crypto/ml-dsa.ts` |
| reject structurally incomplete post-quantum material | `BASE_CERTIFICATE_STRUCTURE_VALID` | `adversarial/Q004` | `REJECTED` | `core/issued/` |
| k-of-n quorum counting (insufficient, non-member, duplicate) | `FOUNDATION_SIGNATURE_VALID` | `adversarial/QN1`-`QN3` | `REJECTED` | `core/foundation/verify-foundation.ts` |
| successor-binding quorum (k-1, non-member, tampered, duplicate signer) | `FOUNDATION_SUCCESSOR_QUORUM_VALID` | `adversarial/QN5`-`QN8` | `REJECTED` | `core/foundation/verify-foundation.ts` |
| foundation equivocation | `FOUNDATION_EQUIVOCATION_DETECTED` | `adversarial/QN4` | `REJECTED` | `core/foundation/verify-foundation.ts` |

The goal is simple: an auditor should be able to move from rule to evidence
without guesswork. For the authoritative per-check failure classification and
public rule source, see `check-catalog.md`.
