# PQC Normative Runtime Decision

This document records the runtime/backend decision for the post-quantum
verification plane in the CERTCRYPT `/1` reference verifier.

---

## 1. Scope

The post-quantum plane is the ML-DSA-65 component of the composite signature.
It is **NORMATIVE** for `/1`. It is not a sidecar, and it is not an additional
verification path that runs alongside the verdict — it is one of the two halves
the verdict is made of.

The normative `/1` authenticity path is the composite signature, whose canonical
profile is `certcrypt-composite-p256-mldsa65-v1` (ECDSA-P256-SHA3-256 AND
ML-DSA-65). `certcrypt-composite-ed25519-mldsa65-v1` swaps the classical half
for Ed25519. Neither profile exists without its ML-DSA-65 component.

A certificate whose composite signature carries no ML-DSA-65 component is
rejected outright: the post-quantum floor cannot be skipped
(`core/crypto/composite.ts`).

---

## 2. Algorithm

The post-quantum algorithm for `/1` is:

```
ML-DSA-65 (FIPS 204)
```

This is the Dilithium-based digital signature scheme standardized by NIST.

---

## 3. Backend

The chosen backend is:

```
@noble/post-quantum (ml-dsa.js)
```

Version: `^0.6.0`

### Why this backend

- Pure JavaScript — no native compilation, no system dependencies
- Works on all Node.js >= 20 runtimes without special setup
- Implements FIPS 204 (ML-DSA) exactly
- Auditable, minimal, well-maintained
- Same runtime baseline as the rest of the toolkit
- No additional system requirements for integrators

### What it provides

- `ml_dsa65.verify(publicKey, message, signature)` — returns boolean
- Key and signature inputs are raw byte arrays
- No key import ceremony — raw bytes in, boolean out

---

## 4. Capability Detection

The runtime is loaded by attempting to import `@noble/post-quantum/ml-dsa.js`.

- If the import succeeds: post-quantum verification is available
- If the import fails (package not installed): `reason = "unsupported_runtime"`,
  and verification of any composite signature returns `UNSUPPORTED`
- The import is dynamic, so it does not block toolkit startup — but a verdict
  cannot be reached until `initMlDsa65()` has run successfully

---

## 5. Key and Signature Encoding

For the ML-DSA-65 component:

- Public key: RFC 4648 base64-encoded raw ML-DSA-65 public key bytes, carried as
  `signer.pub_mldsa_b64`
- Signature: RFC 4648 base64-encoded raw ML-DSA-65 signature bytes, carried as
  the `signatures[]` entry whose `alg` is `ML-DSA-65`
- Message: the composite `M'` bytes, identical for both components — the
  domain-separated encoding defined in `core/crypto/composite.ts`

Strict RFC 4648 base64 validation applies to both fields.

---

## 6. Primitive Error Classification

`verifyMlDsa65Signature` is a primitive, never a verdict. It returns:

| Condition | performed | passed | reason |
|-----------|-----------|--------|--------|
| Runtime cannot import backend | false | null | `unsupported_runtime` |
| Malformed base64 encoding | false | null | `malformed_pqc_material: <detail>` |
| Verification attempted, passed | true | true | null |
| Verification attempted, failed | true | false | `verification_failed` |

These reasons are consumed by `core/issued/verify-issued.ts`, which maps them to
the hard verdicts in §7. They are not reported to the caller as-is.

---

## 7. Normative Boundary

This backend decision is load-bearing for `/1` normative semantics.

The composite is valid only when the classical component AND the ML-DSA-65
component both verify. The verdict is attributed to `BASE_CERTIFICATE_AUTHENTIC`:

| Post-quantum condition | `result_code` | in `failed_check_ids` |
|---|---|---|
| ML-DSA-65 component absent from the signature | `REJECTED` | yes |
| ML-DSA-65 runtime unavailable | `UNSUPPORTED` | yes |
| Malformed ML-DSA-65 material | `REJECTED` | yes |
| ML-DSA-65 component verifies as invalid | `ISSUED_INVALID` | yes |

A valid classical signature does not rescue any of these. The post-quantum
outcome is *additionally* recorded in
`additional_verifications.pqc_base_certificate_authentic` for visibility, but
that field reports the verdict — it does not carry it.

There is no separate check id for the post-quantum component: its verdict is
attributed to `BASE_CERTIFICATE_AUTHENTIC` (verifier-toolkit/1 §9.7).

---

## 8. Dependency Model

`@noble/post-quantum` is listed in `optionalDependencies` in `package.json` for
packaging reasons only: a runtime that cannot install it should still be able to
install the toolkit.

It is **operationally required**. Without it, no composite signature can be
verified and every production verification returns `UNSUPPORTED`. The toolkit
refuses rather than falling back to the classical half alone.

Being optional applies to installation, not to reaching a verdict.

## 9. Status

The post-quantum plane performs real verification, not
placeholder reporting. Dual-signed certificates are first-class fixture
artifacts.
