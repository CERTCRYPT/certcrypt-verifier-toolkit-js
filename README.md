# CERTCRYPT Verifier Toolkit for JavaScript

Official JavaScript/TypeScript reference verifier toolkit for evaluating CERTCRYPT artifacts under public rules without relying on live issuer systems.

CERTCRYPT is infrastructure that makes certification independently verifiable under public rules. Selected artifacts can reach `Independent` through `Proof of Independence`, a structural result, so later verification no longer depends on the issuer's live systems.

This toolkit evaluates CERTCRYPT artifacts under public rules, offline and `fail-closed`, without access to the issuer's live systems.

> [!NOTE]
> **The verifier API is stable at 1.0, and the production profile carries the certified rules corpus commitment.**
>
> The public surface listed under [Public API](#public-api) follows semantic versioning from 1.0.0 on, so anything that breaks it requires a major release. `getCertcryptConfig()` carries the published system root, the XRPL mainnet settlement parameters and the corpus commitment of `rules/2026-01`: `17e3a74a4fd05b039da9f740a138c36d353f561d49726c00351843bb518364ff`, the `subtree_root` of the corpus proof published in certcrypt-specs under `verification/rules/rules-2026-01/`. A rules version whose corpus proof is still pending carries `<pending-corpus-proof>` instead, and every `Independent` verification under it **fails closed** as `REJECTED` under `RULES_CORPUS_COMMITMENT_PRESENT`.

## Purpose

The toolkit evaluates whether an artifact has reached the conditions associated with `Independent`.

`Independent` means that later verification no longer depends on the issuer's live systems, internal databases, vendor continuity, or institutional cooperation.

The verifier role is evaluation under public rules. It is not endorsement, semantic validation, or institutional trust.

### It verifies any deployment, not just CERTCRYPT's

`verify()` takes a `SystemDomainConfig`, and the type is exported. Point it at
your own issuance, your own settlement account, your own rules domain — nothing in
this package is privileged to CERTCRYPT. `.env.example` is the template, field by
field.

`getCertcryptConfig()` is the profile CERTCRYPT publishes, and it is compiled in
rather than configured for one reason: **a verifier must not be configurable into
lying.** If the root fingerprint came from the environment, anyone could
substitute their own and obtain `INDEPENDENT_VALID` over fabricated material.
Shipping the published profile is what makes a verdict independent of whoever
runs the verifier — the same reason browsers ship root CAs instead of reading them
from a file.

Any other profile you supply is equally valid; it simply reports
`production_verification: false`, meaning "verified, but not against the published
CERTCRYPT domain". That flag distinguishes systems — it does not rank them.

Where a design here looks surprising, the reason is stated rather than left to be
inferred. Most of these choices exist because the alternative fails **silently** —
and a verifier that fails silently hands someone a verdict they cannot defend
later, which is the one outcome this package exists to prevent.

## Requirements

- Node.js >= 20, or any modern browser (see "Runtimes" below).
- The post-quantum component uses `@noble/post-quantum`, declared as an `optionalDependency` so a runtime that cannot build it still installs. It is **not** optional to the verdict: ML-DSA-65 is a required half of every composite signature, and without the runtime `BASE_CERTIFICATE_AUTHENTIC` fails `UNSUPPORTED` — the verifier refuses rather than falling back to the classical half alone. Malformed post-quantum material in the certificate fails `REJECTED` instead, so the two are distinguishable.

## Runtimes

The toolkit runs on Node and in the browser, on two crypto backends behind one
interface:

| Runtime | Entry point                                | Primitives                       |
|---------|--------------------------------------------|----------------------------------|
| Node    | `@certcrypt/verifier-toolkit` (or `/node`) | `node:crypto`                    |
| Browser | `@certcrypt/verifier-toolkit/web`          | `@noble/hashes`, `@noble/curves` |

`exports` resolves this automatically — a bundler picks the browser entry, Node
picks the Node entry. Nothing reachable from the browser entry imports
`node:crypto`, `node:fs` or `node:path`, so no aliasing, polyfilling or
`externals` configuration is required.

**Why a browser build exists.** Computing an artifact's commitment requires the
**original material**. Sending that to a server would transmit exactly the
private content the protocol is designed never to require — so the verifier runs
where the material already is, and the material never leaves the machine. This
also removes any practical size ceiling: a large file is hashed locally rather
than uploaded.

WebCrypto alone cannot serve this: it has no SHA-3 at any digest length, and
SHA3-256 is the digest under every commitment in the spec.

In the browser, supply artifacts **in memory** (`base_certificate`,
`independence_proof`, `original_material`, …) rather than by `*_path`;
`VerifierRequest` accepts both forms and the in-memory value wins.
An artifact read from a path is parsed strictly: a member name repeated in any
object, at any depth, rejects the input. An in-memory artifact has already been
parsed by the caller, so parse it with the exported `strictJsonParse`; a parser
that keeps one of two duplicates has already discarded the evidence.

**The browser path is audited, not assumed.** Both backends run the same unit
suite and the same 160 conformance fixtures:

```sh
npm test                      # unit, node backend
npm run test:web              # unit, web backend
npm run test:conformance      # the full fixture set, node backend
npm run test:conformance:web  # the full fixture set, web backend
```

**The verdict half is complete; the primitive half is partial.**
`test:conformance` runs all 160 verdict fixtures, which is what binds a verifier.
The suite also carries 29 families of primitive byte-contract vectors, of which
this toolkit reads 17 — every family a verifier consumes: the subject
canonicalizations, strict JSON, original material, the collection fold,
pseudonyms, holder key sets, capacity evidence and the level-1 binding, the
independence-proof signature, the composite framing and verification, and the
consistency vectors (`core/conformance/coverage.test.ts` names the test that
reads each one).

The 12 it does not read are producer-side (how an issuer assembles and signs what
a verifier later checks) or resolution-side. One of them, `operator-receipt`,
fixes bytes a transporting node signs; no verdict depends on a receipt and this
toolkit handles none. Another, `operator-domain-binding`, fixes the statements by
which a node associates its operator key with a host name; they are no part of
any proof, and this toolkit verifies none.

`core/crypto/provider/provider.equivalence.test.ts` additionally pins the two
backends against each other primitive by primitive, including the cases where
they could plausibly diverge (high-s ECDSA signatures, SHA3-vs-SHA2 digests, and
both accepted public-key encodings).

Neither backend can sign: the provider interface exposes hashing and
signature **verification** only. The toolkit evaluates artifacts under public
rules and holds no secrets.

## Public API

Both entry points expose the **same** surface, so code written against one runs
on the other unchanged (pinned by `core/public-api.test.ts`):

| Export                                                                         | What it is                                               |
|--------------------------------------------------------------------------------|----------------------------------------------------------|
| `verify(request, config?)`                                                     | the verdict — the main entry point                       |
| `verifyCollectionInclusion(...)`                                               | element-level inclusion              |
| `verifyCollectionElementFromCertificate(certificate, value, options?)`         | element-level inclusion from the certificate and one leaf value alone (verifier-toolkit/1 §8.4.2) |
| `collectionLeafHash` / `collectionNodeHash` / `collectionMerkleRoot`, `COLLECTION_MERKLE_SCHEME` | the collection fold, to derive an inclusion proof from signed `leaves[]` |
| `digestHexBytes` / `digestHexText` / `digestBytes`                             | SHA3-256, the digest under every commitment              |
| `digestHexStream`                                                              | SHA3-256 fed in chunks, for material too big to buffer   |
| `isOpaqueByteProfile` / `OPAQUE_BYTE_PROFILES`                                 | which profiles may be hashed in chunks                   |
| `canonicalBytesForSubject`, `SUBJECT_*`, `SUPPORTED_SUBJECT_PROFILES`          | canonical bytes per subject profile             |
| `jcsCanonicalizeBytes` / `jcsCanonicalizeString`                               | RFC 8785 canonicalization — the signed byte form         |
| `strictJsonParse` / `StrictJsonError`                                          | strict JSON, for artifacts passed in memory              |
| `verifyComposite`, `compositeMPrime`, `COMPOSITE_DOMAIN_PREFIX`, `PROFILE_*`, `ALG_*` | composite signature verification (the AND of components) |
| `getCertcryptConfig`                                                           | the CERTCRYPT system-domain profile                      |
| `foundationPayloadDigest` / `FOUNDATION_UNSIGNED_PAYLOAD_FIELDS`               | the signed payload digest of a `system-foundation/1` statement, for a deployment that configures its own |
| `initMlDsa65`                                                                  | starts the ML-DSA-65 runtime the composite requires      |
| `CONFORMANCE_VECTORS_VERSION` / `CONFORMANCE_FIXTURES_PASSED`                  | which conformance vectors this build passed, or `null`   |
| `verifyRulesCorpus(request, documents, config)`                                | checks a rules text against the corpus commitment (`rules-domain/1` §13.3) |
| `verifyConsistency(certificate, snapshots, config?)`                           | CCVP/1 consistency with the declared context the certificate names — optional, reported beside the verdict, never part of it |

The surface is **complete operations, never loose primitives**. Single signature
components (`verifyEd25519Signature`, `verifyEcdsaP256Signature`,
`verifyMlDsa65Signature`) and the holder-keyset Merkle fold internals
(`computeMerkleRoot`, `computeLeafHash`, `generateInclusionProof`) are
deliberately NOT exported: a composite is valid only through `verifyComposite`,
so exporting a component would hand out a way to accept a signature whose
post-quantum half was stripped.

The collection fold (`collectionLeafHash`, `collectionNodeHash`,
`collectionMerkleRoot`) is the one deliberate exception: `subject.collection/1`
§7.4 places the per-leaf commitments inside the signed certificate, so a holder
can derive an inclusion proof for any element from `leaves[]` alone. The verdict
still comes from `verifyCollectionInclusion`, which is fail-closed, and
`verifyCollectionElementFromCertificate` does the whole operation for you: it
verifies the certificate, folds the signed leaves, tries every declared leaf
profile and reports every position a repeated value occupies. `exports` enforces this
— deep imports into `dist/` are blocked, and TypeScript rejects them at compile
time.

`getCertcryptConfig()` is the published CERTCRYPT profile: the system-root
fingerprint and the XRPL mainnet settlement parameters of `rules/2026-01`, and one
corpus commitment per supported `rules_version` (`rules_corpus_roots`). The
commitment of `rules/2026-01` is the `subtree_root` of its corpus proof. It fails
closed: a rules version whose corpus proof has not been emitted carries the
placeholder `<pending-corpus-proof>`, and the toolkit refuses that placeholder as
it refuses a missing value, so no artifact reaches `INDEPENDENT_VALID` under it.
Replacing it with a concrete value before the proof exists is a fail-OPEN bug, not
a fix.

### The rules text is checked against a commitment the toolkit carries

The corpus commitment is the `subtree_root` anchored by the corpus proof of a rules
domain: the proof that fixes which text that `rules_version` is made of (for
`rules/2026-01`, its registry entry). It ships inside the profile, never from the
environment or the ruleset under evaluation, because a commitment that could be
configured could be replaced (`rules-domain/1` §13.3.1).

`verifyRulesCorpus(request, documents, config)` checks a document set against it:
the corpus proof verifies, its `subtree_root` is the commitment `config` carries,
its certificate commits to one `subject.collection/1` of `subject.text/1` leaves,
and each document reproduces its leaf. A valid result means the text is exactly
the one that governs that `rules_version`; it says nothing about whether the rules
are right.

### Only the production profile is a CERTCRYPT verdict

This toolkit verifies any deployment of the protocol: `verify()` takes a
`SystemDomainConfig`, the type is public, and a caller can point it at their own
issuance, their own settlement account and their own rules domain. One profile is
different from all the others, and the distinction is the point.

- **The package ships exactly one profile: production.** The test-profile helpers
  live in `harness/`, which npm excludes. They are not reachable from the package
  — not through `exports`, and not through an internal path either, because the
  files are not there.
- **Running under any other profile requires you to supply it.** The environment
  helper reads every field from the environment and throws when one is missing;
  nothing is defaulted. The conformance helper carries synthetic values only. `certcrypt-verify --test-config <path>` takes a config you own. No
  deployment configuration ships with this repository or the package.
- **A verdict under a non-production profile is not a CERTCRYPT verdict.**
  `VerifierResult.production_verification` is `false` for any configuration that
  is not byte-for-byte the published production profile — not merely a different
  root fingerprint, the *entire* profile. Presenting such a result as a CERTCRYPT
  verification is a misrepresentation.

### Consistency with a declared context is optional, and never a verdict

`verifyConsistency(certificate, snapshots, config?)` answers one question under
CCVP/1: was this certificate issued by a key that the declared context it names
listed as eligible at its issuance time? A certificate names that context in its
signed `payload.context` — the snapshot issuer by `signer.id` **and** composite key
fingerprint, plus a `context_set_id` — and context snapshots are ordinary signed
certificates carrying `payload.snapshot`.

Pass the certificates themselves, parsed with `strictJsonParse`, never extracted
snapshot values. Every one is verified under the Issued route first, and a
snapshot's issuer is the key that signed it: a snapshot signed by another key is
outside the namespace even when it carries the same `signer.id` label. Timestamps
are compared as instants (`…00Z` and `…00.000Z` are the same moment), and the
outcome is `consistency-match`, `consistency-mismatch` or `consistency-unknown`.

None of them changes what `verify()` returns. A match is not endorsement, not
trust and not a step toward Independent; an unknown invalidates nothing.

### Hashing material in chunks

`digestHexStream()` hashes a file piece by piece — `update()` per chunk, then
`digestHex()` — so a multi-gigabyte input never has to exist in one buffer. The
result equals `digestHexBytes()` over the concatenation, and the equivalence test
pins that at chunk sizes straddling SHA3-256's 136-byte rate, which is where a
naive implementation would drift **silently** and produce a wrong commitment
rather than an error.

A caller that streamed a file can then pass `PrehashedMaterial` —
`{ prehashed: true, subject_local_digest_hex }` — in the subject-material map
instead of the bytes. The verdict is identical, because the commitment is computed
from that digest either way.

**This is valid only where `canonical_bytes` ARE the input bytes**, which today
means `subject.binary/1`. Ask `isOpaqueByteProfile(profile)` rather than comparing
the name: the rule lives next to the switch that canonicalizes, so the two cannot
drift apart, and a future profile version with the same property needs no change
here. Every other profile transforms the material before hashing — `subject.text/1`
normalizes line endings, `subject.email/1` unfolds headers across the whole
message, and the JSON-object profiles re-serialize the *parsed value* under JCS —
and none of those is chunk-local. A prehashed entry on one of them is `REJECTED`
as caller misuse, deliberately NOT compared as an `ISSUED_INVALID` material
mismatch: the fault is in the call, not in the material, and reporting it as a
material mismatch would send someone hunting for a tampered file.

## Quickstart

Build the toolkit and run the conformance suite locally.

```sh
git clone https://github.com/CERTCRYPT/certcrypt-verifier-toolkit-js.git
cd certcrypt-verifier-toolkit-js
npm install
npm run build            # compiles TypeScript to dist/
npm test                 # unit tests (node --test)
```

To run the conformance suite you also need the conformance contract. It is not
vendored in this repository (see "Conformance contract" below):

```sh
# Check out the contract repository next to this one
git clone https://github.com/CERTCRYPT/certcrypt-conformance.git ../certcrypt-conformance

npm run test:conformance # runs the verifier against the full fixture set
# -> 160 passed, 0 failed
```

## Repository Layout

- `core/` — the verifier implementation: crypto primitives (SHA3-256, JCS, Merkle, and the composite signature: ECDSA-P256-SHA3-256 or Ed25519, AND ML-DSA-65), the `Issued` and `Independent` verification paths, and the result builder.
- `cli/` — the `certcrypt-verify` command-line entry point.
- `scripts/` — the conformance harness (`run-conformance.ts`), which runs the verifier against the contract in `certcrypt-conformance`.
- `docs/` — the verifier contract, the rule-to-check catalog, and start-here guides for auditors and developers.

## Conformance contract

The conformance fixtures are not vendored here. They are data — schemas plus
test vectors — and live in the [`certcrypt-conformance`](https://github.com/CERTCRYPT/certcrypt-conformance)
repository, produced by its canonical generator. Keeping them in one place means
every language verifier validates against the exact same bytes.

The conformance harness (`npm run test:conformance`) resolves the fixtures in
this order:

1. **`CERTCRYPT_CONFORMANCE_DIR`** — if set, it must point at the `fixtures/`
   directory of a checked-out `certcrypt-conformance`. This takes precedence and
   is the option to use in CI or when the contract lives elsewhere on disk:

   ```sh
   export CERTCRYPT_CONFORMANCE_DIR=/path/to/certcrypt-conformance/fixtures
   npm run test:conformance
   ```

2. **Sibling checkout** — if the variable is not set, the harness looks for
   `certcrypt-conformance/fixtures` next to this repository (i.e.
   `../certcrypt-conformance/fixtures`). This is the convention the Quickstart
   uses, so no environment variable is needed for a side-by-side checkout.

If neither resolves, the harness fails with a message telling you to set
`CERTCRYPT_CONFORMANCE_DIR` or check out the sibling repository.

## CLI

The `certcrypt-verify` CLI is a thin wrapper around the `verify` function. It
prints the structured `VerifierResult` as JSON to stdout and sets the exit code
from the verdict: `0` when `result_code` ends in `_VALID`, `1` for any other
verdict (`*_INVALID`, `INCOMPLETE`, `UNSUPPORTED`, `REJECTED`), and `2` for a
usage error. `--help` (or `-h`) prints the usage to stdout and exits `0`.

Verify by passing artifacts directly:

```sh
node dist/cli/certcrypt-verify.js \
  --certificate base-certificate.json \
  --proof independence-proof.json \
  --settlement-material settlement-material.json \
  --capacity-evidence capacity-evidence.json \
  --commitment-inclusion-proof commitment-inclusion-proof.json \
  --target independent
```

Or pass a single `VerifierRequest` JSON file that names the artifact paths:

```sh
node dist/cli/certcrypt-verify.js --request request.json
```

```jsonc
// request.json — paths are resolved relative to the current working directory
{
  "verification_target_requested": "independent",  // "auto" (default) | "issued" | "independent"
  "input_mode": "artifact_set",                     // "artifact_set" | "package"
  "base_certificate_path": "base-certificate.json",
  "independence_proof_path": "independence-proof.json",
  "settlement_material_path": "settlement-material.json",
  "capacity_evidence_path": "capacity-evidence.json",
  "commitment_inclusion_proof_path": "commitment-inclusion-proof.json"
}
```

All flags (`certcrypt-verify --help`):

| flag | meaning |
|---|---|
| `--request <path>` | a `VerifierRequest` JSON file (alternative to the flags below) |
| `--certificate <path>` | base certificate JSON (required unless `--request` is used) |
| `--proof <path>` | independence proof JSON (needed for `Independent`) |
| `--settlement-material <path>` | settlement material JSON |
| `--capacity-evidence <path>` | the capacity evidence of the certificate's commitment |
| `--commitment-inclusion-proof <path>` | the per-commitment inclusion proof |
| `--package <path>` | a `verification_package` JSON; carries the certificate and the Independent artifacts, so it is not combined with the per-artifact flags |
| `--foundation <path>` | `system-foundation/1` statement JSON |
| `--original-material <path>` | subject-material manifest for complete verification against original material |
| `--target <auto\|issued\|independent>` | verification target; defaults to `auto` |
| `--test-config <path>` | TEST-ONLY: verify under a `SystemDomainConfig` JSON file you supply instead of the published production profile; every signature is still verified |
| `--test-root-fingerprint <hex>` | TEST-ONLY: override `system_root_fingerprint` in the `--test-config` profile; requires `--test-config` |
| `-h`, `--help` | print usage to stdout and exit `0` |

> [!IMPORTANT]
> **Without the test-only flags, the CLI runs in production mode.** It
> verifies against the published CERTCRYPT production profile, so running it
> against the conformance fixtures — which are signed with a synthetic test root —
> returns no `*_VALID` verdict: most fixtures carry their own test foundation
> statement and return `REJECTED` with `FOUNDATION_BOOTSTRAP_MATCHES_RULES` in
> `failed_check_ids`. That is expected. The conformance fixtures are exercised
> under the test configuration by `npm run test:conformance`; no test profile is
> built into the CLI. `--test-config` and `--test-root-fingerprint` let a test or
> self-hosted deployment supply its own profile as a file, and any verdict under a
> profile other than the published one reports `production_verification: false`,
> so a test verdict can never be mistaken for a real one.

## What an Independent verdict rests on

An `Independent` verdict rests on three elements — the certificate, the `Proof of
Independence` and the public rules. The original material adds a fourth, opt-in
comparison. Each enters the verifier differently, and only two are files you hand it:

1. **The certificate** — the base certificate, supplied with `--certificate`
   (or `base_certificate_path`). This is the artifact whose subjects and claims
   are being verified.

2. **The `Proof of Independence`** — supplied as the independence proof
   (`--proof`) with the artifacts that bind it to this certificate: its
   settlement material (`--settlement-material`), the capacity evidence of the
   certificate's commitment (`--capacity-evidence`) and the per-commitment
   inclusion proof (`--commitment-inclusion-proof`), or all of them at once in a
   `verification_package` (`--package`). Together these carry the structural
   proof that the certificate reached `Independent`.

3. **The public rules** — NOT a file you pass. The applicable `rules_version` is
   embedded in, and signed as part of, the certificate and the proof. The
   verifier reads it from there and resolves it against the rule set it
   implements (its `supported_rules_versions`); a rules version it does not
   support fails closed as `UNSUPPORTED`. The public rules are the normative
   frame under which evaluation happens, not an input the holder attaches — so
   there is no `--rules` flag.

4. **The original material** — a *separate, opt-in verification plane*.
   The structural `Independent` baseline (elements 1–3) does **not** require it:
   without material the verifier reports `ORIGINAL_MATERIAL_COMPARISON_VALID` as
   *not performed* and the `Independent` verdict still stands. Supplying it with
   `--original-material` turns on *complete verification against original
   material*: the verifier recomputes each subject's `canonical_bytes` under its
   declared profile, rebuilds the CCCP/1 commitment, and confirms it matches
   what the certificate committed to. This is the distinction between
   *verification* (the technical act, elements 1–3) and *complete evaluation
   against the material* (element 4).

   The material is delivered as a **subject-material manifest** — a JSON array,
   one entry per subject in `anchor.subjects[]` order, that points at the byte
   files. The manifest never declares a subject's `profile`: the profile
   (`subject.binary/1`, `subject.text/1`, `subject.email/1`,
   `subject.collection/1`, …) is read from the certificate, which is the sole
   source of what each subject is. A single-blob subject points at one file; a
   collection points at its ordered leaf files — its descriptor is NOT part of the
   delivery, because `subject.collection/1` §7 puts it inside the signed subject:

   ```jsonc
   // original-material.json — paths resolved relative to this manifest's directory
   [
     { "material_file": "subject-0.bin" },                              // binary/text/email/…: one blob
     { "leaf_files": ["leaf-0.bin", "leaf-1.bin", "leaf-2.bin"] },       // a collection's ordered leaves
     { "material_file": "decision.json",                                // an AI-decision record, and
       "materials": [{ "id": "prompt", "material_file": "prompt.txt" },
                     { "id": "image", "prehashed": true,
                       "subject_local_digest_hex": "..." }] }
   ]
   ```

   For a `subject.ai-decision/1` subject, every nested part is optional and keyed by
   its id in the record. Once the record has matched the certificate, each disclosed
   part is canonicalized under the `profile` that matched record declares. The toolkit
   derives its salted commitment from the descriptor's `material_nonce_hex` and the
   verifier-local subject digest, then compares it with `commitment_digest_hex`. A binary
   part may carry a verifier-local streaming digest in place of its bytes. A match
   identifies the held material named by the committed record; it says nothing about the
   decision's merit.

## CERTCRYPT boundary

- not a claim of factual truth
- not a validator of correctness
- not a custodian of documents
- not blockchain notarization
- not a trust badge

## Boundary of this verifier toolkit

- not a determiner of semantic truth, legal validity, or factual correctness
- not a substitute for the public rules under which an artifact is evaluated
- not an endorsement of the issuer or of the underlying material
- not a live dependency that later verification must rely on

It evaluates verification state under public rules.

### Trademarks

The Apache-2.0 grant covers copyright, not marks: §6 of the license grants no
permission to use CERTCRYPT trade names, trademarks, service marks or product
names beyond describing the origin of the work.

Stating that your product verifies CERTCRYPT artifacts, or that it uses this
toolkit, is such a use. Naming your product after CERTCRYPT is not, and neither
is presenting a verdict this toolkit produced as CERTCRYPT having endorsed,
certified or approved the artifact: the toolkit evaluates under public rules and
returns a result, which is not an act of the issuer or of CERTCRYPT. A verdict is
reproducible by anyone holding the same artifacts — that is what makes it worth
citing, and what it stays.

## Properties

The verifier is built around:

- deterministic verification behavior
- independent evaluation under public rules
- `fail-closed` handling of invalid or incomplete inputs
- no dependency on issuer live systems for later verification
- clear separation between `Issued` and `Independent`
- no semantic inflation of verification results

## Documentation

Technical documentation and the public specifications are published at
[docs.certcrypt.com](https://docs.certcrypt.com): the model, the terminology, the
claims boundary, the evaluation model this toolkit applies, and the normative
specifications it verifies against.

## Links

| Surface | Address |
| --- | --- |
| Website | [certcrypt.com](https://certcrypt.com) |
| Documentation | [docs.certcrypt.com](https://docs.certcrypt.com) |
| Verify an artifact | [verify.certcrypt.dev](https://verify.certcrypt.dev) |
| Blog | [blog.certcrypt.com](https://blog.certcrypt.com) |
| Support | [support.certcrypt.com](https://support.certcrypt.com) |
| Service status | [status.certcrypt.com](https://status.certcrypt.com) |
| Open source | opensource@certcrypt.com |
| Security | security@certcrypt.com — see [`SECURITY.md`](SECURITY.md) |

**The two repositories on either side of this one:**

| Repository | Relationship |
| --- | --- |
| [certcrypt-conformance](https://github.com/CERTCRYPT/certcrypt-conformance) | the contract this toolkit is audited against — the fixtures it runs, and the version it reports as `CONFORMANCE_VECTORS_VERSION` |
| [certcrypt-sdk-js](https://github.com/CERTCRYPT/certcrypt-sdk-js) | the issuer-side SDK that emits the certificates this toolkit verifies and assembles their `verification_package` |

The contract is data rather than code, so it is what keeps every language binding
honest: the identical fixture must produce the identical `VerifierResult`
everywhere. The SDK is on the other side of the same contract — it emits under
the rules this toolkit evaluates, and its own suite round-trips what it emits
through this verifier.

**This toolkit, hosted:** [verify.certcrypt.dev](https://verify.certcrypt.dev) is
a free, account-less verification service running *this* package in the browser —
the same code, the same verdict, no installation. It reports which toolkit version
and which conformance vectors produced each result, so a report it generates can be
reproduced with a pinned install of this package.

## Changelog

Release notes are in [`CHANGELOG.md`](CHANGELOG.md). From 1.0.0 this package
follows semantic versioning without reservation: a patch fixes behavior, a minor
adds surface without breaking what exists, and anything that breaks a documented
export waits for the next major. Deliberately NOT covered by that promise, because
it is not part of the API: which verdict a given artifact receives. A verifier that
could never tighten a check would be a worse verifier — if a release makes a
previously-accepted artifact fail, that is a corrected verdict and the entry says
so outright.

Each release section also names, in a `Conformance` line, the conformance
vectors that release was verified against — the value a build that ran them
exports as `CONFORMANCE_VECTORS_VERSION`.

`CHANGELOG.md` is one line per change and nothing else: `feature:`, `bugfix:`,
`breaking:`, `deprecation:`, `security:` or `docs:`, then the scope, under a
`## 1.0.0` heading. That keeps it greppable — `grep breaking:` answers "what has
ever broken?" without reading a word — and it is why the reasoning behind a design
stays here instead. The CHANGELOG answers *what changed*; this file answers *why it
is that way*.

It carries no release dates. The publish date is authoritative in the registry and
the git tag:

```bash
npm view @certcrypt/verifier-toolkit time     # every version's publish date
git log -1 --format=%aI v1.0.0                # the tagged commit's date
```

## License

Copyright 2025-2026 CERTCRYPT, Inc., its affiliates or licensors. All rights reserved.

Licensed under the Apache License, Version 2.0. See [`LICENSE`](LICENSE) for the full text.
