# Auditors

If you want to audit the verifier, use this path:

1. read the verifier contract
2. review the rule-to-check map
3. inspect the conformance fixtures
4. trace the implementation in `core/`

What an auditor should find quickly:

- what the toolkit claims to support
- what it must reject
- which checks are mandatory for `Issued`
- which checks are mandatory for `Independent`
- how `auto` target resolution behaves
- where each mandatory behavior is exercised by fixtures

Fast orientation map:

- entry contract: `docs/architecture/verifier-contract.md`
- repository map: `docs/architecture/repository-layout.md`
- rule/check traceability: `docs/audit/check-catalog.md`
- conformance traceability: `docs/audit/conformance-map.md`
- expected evidence: the `certcrypt-conformance` fixtures (`conformance/` + `adversarial/`)
- implementation path: `core/`
