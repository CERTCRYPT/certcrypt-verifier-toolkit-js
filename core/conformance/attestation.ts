/**
 * The version of the conformance vectors this build passed.
 *
 * ## Why this file is generated, and why it defaults to "unverified"
 *
 * The toolkit's own version says which code ran. It does not say what that code
 * was held to. Those are different claims, and a report that promises "anyone can
 * reproduce this with the same toolkit" needs both: the toolkit, and the contract
 * the toolkit was audited against.
 *
 * The honest source for the second claim is the conformance runner — the only
 * process that actually executes the vectors. So this value is WRITTEN BY that
 * runner (`scripts/run-conformance.ts`), on success, from the `VERSION` file of
 * the `certcrypt-conformance` checkout it just ran against. It is never authored
 * by hand, and a consumer must not treat it as a string that can be edited: if it
 * says `1.0.0`, that is because this build passed the 1.0.0 vectors.
 *
 * The committed value below is the FAILED-CLOSED default: `null`. A checkout that
 * has never run the suite — a local build without the sibling repos, a fresh
 * clone — reports `null` rather than inheriting whatever number was last
 * committed. `null` is a true statement ("this build has not been shown to pass
 * any vector set"); a stale version number is a false one. A consumer that cannot
 * distinguish the two would publish an unbacked claim, which is precisely the
 * failure this module exists to prevent.
 *
 * The runner fails the suite if the vectors are absent, if their `VERSION` is
 * unreadable, or if any fixture fails — so there is no path by which a version is
 * recorded without the work having been done.
 */

/**
 * The `certcrypt-conformance` contract version whose vectors this build passed,
 * or `null` when the conformance suite has not been run against this build.
 *
 * Callers MUST handle `null` by showing nothing — not by substituting a default,
 * a "latest known" value, or the version of a conformance checkout they can see
 * for themselves. The absence of a value is the finding.
 */
export const CONFORMANCE_VECTORS_VERSION: string | null = null;

/**
 * The number of fixtures that passed when `CONFORMANCE_VECTORS_VERSION` was
 * recorded, or `null` alongside it. Reported for the same reason: a version
 * without a count says which contract, but not how much of it was exercised.
 */
export const CONFORMANCE_FIXTURES_PASSED: number | null = null;
