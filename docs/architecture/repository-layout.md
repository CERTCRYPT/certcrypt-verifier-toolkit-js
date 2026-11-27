# Repository Layout

This repository is the JavaScript/TypeScript reference verifier. It is a
single-language toolkit, not a multi-language monorepo.

```text
certcrypt-verifier-toolkit-js/
├── README.md
├── CHANGELOG.md
├── LICENSE
├── SECURITY.md
├── .gitignore
├── package.json
├── tsconfig.json
├── core/            # normative verifier semantics
│   ├── config/      # the published production profile
│   ├── conformance/ # conformance attestation constants
│   ├── crypto/      # SHA3-256, JCS, Merkle, composite (ECDSA-P256 + ML-DSA-65 /
│   │   │            #   Ed25519 + ML-DSA-65), pseudonym
│   │   └── provider/ # pluggable node/web crypto backend
│   ├── input/       # request parsing, target resolution, strict JSON
│   ├── foundation/  # system-foundation/1 verification
│   ├── domain/      # system-domain attribution
│   ├── rules/       # rules-domain selection
│   ├── issued/      # Issued path
│   ├── independent/ # Independent path
│   ├── package/     # verification-package handling
│   ├── result/      # fail-closed result builder
│   ├── testing/     # output-schema conformance helpers
│   └── types/       # artifact, proof, result, check types
├── harness/         # non-production profiles (conformance, environment-supplied), not exported
├── cli/             # certcrypt-verify command-line entry point
├── scripts/         # run-conformance.ts (conformance harness)
└── docs/
    ├── start-here/
    ├── architecture/
    └── audit/
```

## Rules

- normative semantics live in `core/`
- `harness/` holds the non-production profiles; they are deliberately not exported from the package — see the reasoning in `core/public-api.ts`
- the developer-facing entry points are the `verify` function (`core/verify.ts`) and the `certcrypt-verify` CLI (`cli/`)
- `docs/start-here/developers.md` is the fastest orientation path for integrators
- `docs/start-here/auditors.md` is the fastest orientation path for audit work
- the conformance contract (fixtures + schemas) is NOT vendored here: it lives in the `certcrypt-conformance` repository, produced by its canonical generator; the harness resolves it from a sibling checkout or `CERTCRYPT_CONFORMANCE_DIR`
- the CLI and the `verify` entry point must answer two questions quickly:
  - how do I verify `Issued`?
  - how do I verify `Independent`?
- every audit document must help trace: public rule -> check -> fixture -> implementation path
