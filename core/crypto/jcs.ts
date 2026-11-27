/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * Per CCCP/1: the canonical form for payload signing uses RFC 8785.
 * This means lexicographic key ordering, no extra whitespace,
 * and deterministic number serialization.
 */
export function jcsCanonicalizeBytes(obj: unknown): Uint8Array {
  const canonical = jcsStringify(obj);
  return new TextEncoder().encode(canonical);
}

export function jcsCanonicalizeString(obj: unknown): string {
  return jcsStringify(obj);
}

function jcsStringify(value: unknown): string {
  if (value === null) return "null";
  if (value === undefined) return "null";

  const t = typeof value;

  if (t === "boolean") return value ? "true" : "false";

  if (t === "number") {
    // RFC 8785 §3.2.2.3 mandates the ECMAScript Number-to-String algorithm.
    // JS `String(n)` IS that algorithm, so it matches byte-for-byte for every
    // finite double, including the cases sometimes assumed to diverge:
    // `String(-0) === "0"` (RFC 8785 requires the negative-zero sign be dropped),
    // exponent form for |n| ≥ 1e21 or < 1e-6, and large integers. Infinity/NaN
    // are not valid JSON and are rejected. Note the string-only subject profiles
    // (collection/ai-decision/context-snapshot) never reach this branch — their
    // preconditions reject any JSON number before canonicalization; this branch
    // serves numbers only in certificate structures (anchor/payload/proof).
    if (!isFinite(value as number)) {
      throw new Error("JCS does not support Infinity or NaN");
    }
    return String(value);
  }

  if (t === "string") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const items = value.map((v) => jcsStringify(v));
    return "[" + items.join(",") + "]";
  }

  if (t === "object" && value !== null) {
    const obj = value as Record<string, unknown>;
    // RFC 8785 §3.2.3: sort keys by UTF-16 code unit. JS `Array.prototype.sort()`
    // on strings compares by UTF-16 code unit, which is exactly this (and differs
    // from code-point order only for supplementary-plane keys — do NOT "fix" this
    // to a code-point sort).
    const keys = Object.keys(obj).sort();
    const members = keys
      .filter((k) => obj[k] !== undefined)
      .map((k) => JSON.stringify(k) + ":" + jcsStringify(obj[k]));
    return "{" + members.join(",") + "}";
  }

  throw new Error(`JCS: unsupported type ${t}`);
}
