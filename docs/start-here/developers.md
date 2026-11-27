# Developers

This guide takes you from a clean checkout to a verification result. For build
and conformance setup, see the README Quickstart; this page focuses on calling
the verifier and reading what it returns.

## The one entry point

Everything goes through a single function, `verify(request, config?)`, exported
from the package root (`core/verify.ts`). The CLI (`certcrypt-verify`) is a thin
wrapper around it. There is no other way to verify.

The second argument selects a non-default system-domain profile; omitted, it uses
`getCertcryptConfig()`. Note that `initMlDsa65()` must have run successfully
before the post-quantum component of a composite signature can be verified —
without it, verification returns `UNSUPPORTED` rather than a verdict.

```ts
import { verify } from "@certcrypt/verifier-toolkit";
import type { VerifierRequest } from "@certcrypt/verifier-toolkit";

// Working from a checkout instead of an install? The same symbols are in the built
// output, after `npm run build`:
//   import { verify } from "./dist/core/verify-node.js";

const request: VerifierRequest = {
  verification_target_requested: "auto", // "auto" | "issued" | "independent"
  input_mode: "artifact_set",            // "artifact_set" | "package"
  base_certificate_path: "base-certificate.json",
  independence_proof_path: "independence-proof.json",
  settlement_material_path: "settlement-material.json",
  capacity_evidence_path: "capacity-evidence.json",
  commitment_inclusion_proof_path: "commitment-inclusion-proof.json",
};

const result = verify(request);
console.log(result.result_code); // e.g. "INDEPENDENT_VALID"
```

`verify` reads the artifact files named in the request — or uses their in-memory
counterparts, which take precedence when both are supplied — runs the
verification, and returns a `VerifierResult`. It never throws on a bad artifact: malformed or
incomplete input is reported `fail-closed` as a verdict, not an exception.

## Choosing a target

- `auto` (the default) resolves to `Independent` when ANY artifact of the
  `Independent` route is supplied — the proof, settlement material, capacity
  evidence or a commitment inclusion proof — and to `Issued` only when none is
  (verifier-toolkit/1 §11.4). Independent evidence without its proof is
  `INCOMPLETE`, never an `Issued` answer.
- `issued` and `independent` force a specific target.

The target you asked for is echoed as `verification_target_requested`; the one
actually evaluated is `verification_target_resolved`.

## Reading the result

The verdict is one `result_code`:

| result_code | meaning |
|---|---|
| `ISSUED_VALID` | the `Issued` path completed and passed |
| `ISSUED_INVALID` | the `Issued` path completed and failed |
| `INDEPENDENT_VALID` | the `Independent` baseline completed and passed |
| `INDEPENDENT_INVALID` | the `Independent` baseline completed and failed |
| `INCOMPLETE` | a required artifact or proof material was missing |
| `UNSUPPORTED` | a version, model, or capability is not implemented |
| `REJECTED` | input was malformed, ambiguous, or otherwise non-conformant |

When a verdict is not `*_VALID`, these fields tell you why:

- `failed_check_ids` — the specific checks that failed (see `docs/audit/check-catalog.md` for what each one means)
- `failure_reason` — a human-readable explanation
- `required_artifacts_missing` — artifacts the requested path needed but did not receive
- `diagnostics` — `info`/`warning`/`error` notes, each tagged with a `check_id`

`INDEPENDENT_VALID` means only that the required offline baseline completed under
public rules. It does not assert truth, legitimacy, legal validity, or
endorsement. Complete verification against the original material is a separate
step, reported in `complete_verification_against_original_material_*`.

## Running it from the CLI

The same request, run from the command line, prints the full result as JSON and
sets the exit code from the verdict (`0` for `*_VALID`, `1` otherwise):

```sh
node dist/cli/certcrypt-verify.js \
  --certificate base-certificate.json \
  --proof independence-proof.json \
  --settlement-material settlement-material.json \
  --capacity-evidence capacity-evidence.json \
  --commitment-inclusion-proof commitment-inclusion-proof.json \
  --target independent
```

See the README "CLI" section for every flag and the production-vs-test note.

## Fast orientation map

- entry point: `core/verify.ts` (programmatic), `cli/certcrypt-verify.ts` (CLI)
- request and result types: `core/types/request.ts`, `core/types/result.ts`
- reference semantics: `core/`
- what each check means: `docs/audit/check-catalog.md`
- conformance contract: the `certcrypt-conformance` repository (run with `npm run test:conformance`)
