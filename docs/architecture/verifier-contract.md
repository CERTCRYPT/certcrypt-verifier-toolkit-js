# Verifier Contract

## Verification Targets

The reference toolkit must support:

- `Issued`
- `Independent`

The public CLI and language wrappers should expose one command:

- `verify`

The requested target should be selectable as:

- `auto`
- `issued`
- `independent`

`auto` should be the default.

If no `--target` is provided, the verifier should behave exactly as if `--target auto` had been provided.

## Input Modes

The reference toolkit must support:

- `package`
- `artifact_set`

`verification_package` is an optional convenience container.

Equivalent artifacts supplied independently under the same public rules must remain valid input.

## Result Taxonomy

The reference toolkit must emit one primary `result_code`:

- `ISSUED_VALID`
- `ISSUED_INVALID`
- `INDEPENDENT_VALID`
- `INDEPENDENT_INVALID`
- `INCOMPLETE`
- `UNSUPPORTED`
- `REJECTED`

## Required Result Fields

The structured result must expose at least:

- `verification_target_requested`
- `verification_target_resolved`
- `verification_target`
- `input_mode`
- `production_verification` — true only when the ENTIRE configuration equals the
  published production profile (every field that defines the production
  environment: system id, root fingerprint, XRPL chain id, MPT issuance,
  settlement account, token symbol, action name, signature profile, foundation
  statement id and payload digest, admitted subject profiles, settlement profile,
  supported rules versions and their corpus roots). A `*_VALID` result with this
  false is NOT a production verdict and must not be relied on for any
  conformance claim.
- `domain_valid`
- `rules_domain_valid`
- `issued_valid`
- `independent_valid`
- `proof_complete`
- `complete_verification_against_original_material_performed`
- `complete_verification_against_original_material_passed`
- `failure_reason`
- `failed_check_ids`
- `required_artifacts_missing`
- `applicable_rules_version`
- `system_id`
- `system_root_identifier`

## Prohibited Success

The toolkit must not emit `INDEPENDENT_VALID` when:

- a required check was omitted
- a required artifact was missing
- parser ambiguity remained
- a fallback or compatibility heuristic was applied
- any required validation remained partial

## Semantic Boundary

`INDEPENDENT_VALID` means only that the required offline baseline completed successfully under public rules.

It does not mean:

- truth
- legitimacy
- legal validity
- institutional endorsement
- complete verification against original material

## Resolution Rule

`verification_target_requested = "auto"` must not become semantic downgrade.

It means:

- resolve to `Independent` only when the required `Independent` baseline can actually be executed
- resolve to `Issued` only when the supplied artifacts support `Issued` but do not support `Independent`
- return `INCOMPLETE`, `UNSUPPORTED`, or `REJECTED` when the input claims or strongly implies an `Independent` path that cannot be completed under public rules

The verifier must not silently present a partial `Independent` attempt as successful `Issued` verification without making the resolved target explicit.
