# Conformance Status

This document records the current conformance status of the reference
`certcrypt-verifier-toolkit`.

---

## 1. Current Status

The toolkit is the reference offline verifier for CERTCRYPT `/1`.

Production authenticity is cryptographically closed for `/1` using the composite
signature profile `certcrypt-composite-p256-mldsa65-v1` (ECDSA-P256-SHA3-256 AND
ML-DSA-65), with `certcrypt-composite-ed25519-mldsa65-v1` as the Ed25519 variant.
The published production profile carries the system root, the settlement
parameters and the corpus commitment of `rules/2026-01` (the `subtree_root` of its
corpus proof); a rules version whose corpus proof is pending carries
`<pending-corpus-proof>` and fails closed (`rules-domain/1` §13.3.1), so no artifact
under it reaches `INDEPENDENT_VALID`.

The post-quantum plane performs real ML-DSA-65 (FIPS 204) verification as the
required PQC component of the composite, using `@noble/post-quantum`. It is
NORMATIVE for `/1`: a missing, failing, or unverifiable ML-DSA-65 component
prevents a `*_VALID` verdict.

Dual-signed artifacts are first-class, with a single normative `/1` meaning.

The conformance suite passes 160/160, compared with exact equality of `result_code`, `verification_target`, the set of `failed_check_ids` and every further member a fixture declares.

This build reports `CONFORMANCE_VECTORS_VERSION` and `CONFORMANCE_FIXTURES_PASSED`
as written by `npm run test:conformance`. The committed source declares both
`null` (`core/conformance/attestation.ts`) — the fail-closed default meaning the
suite has not been run against this checkout. A checkout that has run the suite
against `certcrypt-conformance` `1.0.0` reports `"1.0.0"` and `160`.

---

## 2. What Is Closed

### 2.1 Production Authenticity

`BASE_CERTIFICATE_AUTHENTIC` uses real composite signature verification
(classical component AND ML-DSA-65), under every configuration.

For `/1`, the normative production authenticity path is the **composite
signature**. Ed25519 is one of two possible classical components, and the
canonical profile uses ECDSA-P256-SHA3-256.

### 2.2 The Post-Quantum Plane

The ML-DSA-65 component is verified via `@noble/post-quantum` as part of every
composite signature. It is NORMATIVE:

- the composite is valid only when the classical component AND the ML-DSA-65
  component both verify
- a missing ML-DSA-65 component is `REJECTED` — the PQC floor cannot be skipped
- a failing ML-DSA-65 component is `ISSUED_INVALID`
- malformed ML-DSA-65 material is `REJECTED`
- an unavailable ML-DSA-65 runtime is `UNSUPPORTED`

All four land in `failed_check_ids` as `BASE_CERTIFICATE_AUTHENTIC` and set
`result_code`. A valid classical signature does not rescue any of them.

The outcome is *additionally* reported in
`additional_verifications.pqc_base_certificate_authentic` for visibility. It has
no check id of its own (verifier-toolkit/1 §9.7).

If the backend is not available (`@noble/post-quantum` not installed), the
post-quantum floor cannot be asserted and verification returns `UNSUPPORTED`. It
blocks. The package is an `optionalDependency` for packaging reasons only; it is
operationally required.

See [`docs/audit/pqc-normative-runtime.md`](./pqc-normative-runtime.md).

### 2.3 Verification Structure

- strict input handling: RFC 8259 JSON, and a member name repeated in any
  object at any depth rejects the input (artifacts and JSON subject material)
- the CCSP/1 envelope checked in full: closed top level, anchor, issuer
  signature and signer; reserved names; `issued_at`, `root_id` and digest
  formats; exactly one issuer signature; published digests recomputed
- fail-closed result construction
- explicit `Issued` vs `Independent` separation
- deterministic target resolution, no silent semantic downgrade

### 2.4 Domain, Rules, Independent Path

- exact system-domain and rules-domain attribution
- aggregated settlement-only `/1` path with Merkle recomputation
- anti-splicing, anti-replay, clone/fork rejection, issuance participation

### 2.5 Result Clarity

- stable result taxonomy, granular check reporting
- `certcrypt_lineage` block: a compact projection of the validated binding
- `additional_verifications` block for post-quantum plane visibility

### 2.6 Foundation Support

`system-foundation/1` with offline verification of a k-of-n quorum of composite
signatures (ECDSA P-256 AND ML-DSA-65) and bootstrap matching enforcement.

---

## 3. Production vs Test Configuration

### 3.1 Production (`getCertcryptConfig`)

- `system_root_fingerprint`, `foundation_statement_id`, `foundation_payload_digest`
  and the settlement parameters of `rules/2026-01`, as the registry entry
  publishes them, and the bootstrap statement itself (used when a request
  supplies none, and validated against those pins on every use); and the corpus
  commitment of `rules/2026-01` (the `subtree_root` of its corpus proof); a rules
  version whose corpus proof is pending fails closed (`rules-domain/1` §13.3.1)
- composite cryptographic verification required (classical AND ML-DSA-65)

### 3.2 Test (`getConformanceConfig` / `getEnvConfig`)

Defined in `harness/profiles.ts` and deliberately **not exported** from the
package — see the reasoning in `core/public-api.ts`.

- Synthetic root from fixed test keypairs
- Every signature is verified, exactly as under the production profile: the
  configuration has no field that could switch verification off

### 3.3 Fixture Categories

| Series | Count | Purpose |
|--------|-------|---------|
| P001-P008 | 8 | Positive Independent path |
| P009 | 1 | Successor binding authorized by the predecessor quorum |
| P010 | 1 | Proof with a node attestation, reported as `attested_node` |
| P011 | 1 | AI-decision subject with its input and output material compared (§8.5.6) |
| P012 | 1 | Commitment issued at the authorization window's opening instant (inclusive boundary) |
| P013 | 1 | Issued verification against original material (target `issued`) |
| P014-P015 | 2 | Verification from a `verification_package` (Independent; Issued) |
| P016 | 1 | Issued verification of an equivalent `subject.email/1` serialization |
| V001-V083 | 83 | Adversarial negative vectors (V065 Issued material mismatch, V066 undeclared subject index, V067 unsupported collection scheme, V068 `auto` with Independent evidence and no proof, V069-V073 packages, V074 opaque subject delivered as records, V075 `independence_result` other than `independent`, V076 holder authorization for another role, V077-V081 closed capacity-evidence shape and canonical scalars, V082 transit-mutated email material, V083 Independent-route material without a base certificate) |
| F001-F018 | 18 | Foundation validation (`F001`, `F005` positive; `F004` a second statement over the registered bootstrap; `F010`-`F018` closed shapes of the statement and the bootstrap manifest, one key encoding, Ed25519 root) |
| S001-S011 | 11 | Signature authenticity (`S001`, `S006` positive; `S007` node attestation altered, `S008` unsigned proof; `S009`-`S011` composite layout: components reordered, `low_s` false, extra member) |
| Q001-Q005 | 5 | Post-quantum dual-sign (valid, invalid, malformed, incomplete) |
| QN1-QN8 | 8 | k-of-n quorum counting: statement quorum (insufficient, non-member, duplicate), equivocation, successor-binding quorum (k-1, non-member, tampered, duplicate) |
| C001-C019 | 19 | CCSP/1 envelope (`C001` positive with every optional member; reserved names, closed objects, formats, a second issuer signature, published digests, domains, component order, repeated member names) |

Total: 160 fixtures.

---

## 4. Dual-Sign Model

The current model means:

- the classical component always verified (normative `/1`)
- ML-DSA-65 always verified as the required post-quantum floor (normative `/1`)
- same artifacts produce same normative `/1` result across runtimes
- dual-sign artifacts are first-class

It does **not** mean:

- two independent normative `/1` authenticity paths — there is one composite,
  made of two components that must both verify
- runtime-dependent verifier meaning

---

## 5. Summary

- verifier core: closed
- production authenticity (composite): closed
- post-quantum plane (ML-DSA-65): real, normative
- conformance suite: 160/160
- dual-sign model: active
