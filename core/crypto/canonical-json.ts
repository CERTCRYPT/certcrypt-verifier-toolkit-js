/**
 * Build canonical JSON bytes from an ordered list of key-value pairs.
 *
 * Per settlement.binding/1 sections 5-6 and system-foundation/1:
 * - UTF-8 encoding
 * - Exact member order as prescribed (NOT sorted)
 * - No additional members
 * - Values may be strings, numbers, booleans, null, or arrays thereof
 *
 * We build the JSON string by explicit concatenation to guarantee
 * exact field order regardless of JS engine object key ordering.
 */
export type CanonicalJsonValue =
  | string
  | number
  | boolean
  | null
  | string[]
  | number[]
  | boolean[];

export function canonicalJsonBytes(
  orderedFields: [string, CanonicalJsonValue][]
): Uint8Array {
  const parts: string[] = ["{"];
  for (let i = 0; i < orderedFields.length; i++) {
    if (i > 0) parts.push(",");
    const [key, value] = orderedFields[i];
    parts.push(JSON.stringify(key) + ":" + JSON.stringify(value));
  }
  parts.push("}");
  const json = parts.join("");
  return new TextEncoder().encode(json);
}
