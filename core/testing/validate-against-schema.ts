/**
 * Minimal, dependency-free JSON Schema validator — just enough of Draft 2020-12
 * to gate the VerifierResult against the frozen normative schema at
 * `certcrypt-conformance/schemas/output/verifier-result.schema.json` on every
 * `npm test`, WITHOUT adding a JSON-schema engine (ajv, etc.) to a toolkit
 * that keeps its runtime dependencies to the audited @noble primitives.
 *
 * Supports exactly the keywords the CERTCRYPT schemas use: `type` (string,
 * boolean, object, array, null, and unions thereof), `enum`, `required`,
 * `properties`, `additionalProperties: false`, `items`, `uniqueItems`. Anything
 * outside that surface throws — so a schema that grows a keyword we don't handle
 * fails loudly rather than validating vacuously. This is a TEST-ONLY helper (it
 * lives under core/testing and is never imported by the verifier itself).
 */

type Json = unknown;
interface Schema {
  type?: string | string[];
  enum?: Json[];
  const?: Json;
  required?: string[];
  properties?: Record<string, Schema>;
  additionalProperties?: boolean;
  items?: Schema;
  uniqueItems?: boolean;
  // Annotation and envelope keys, intentionally ignored during validation.
  //
  // These are documentation, not constraints: per Draft 2020-12 an annotation
  // never causes an instance to fail. Ignoring them is therefore not a gap in
  // coverage — validating them would be meaningless. Every keyword that DOES
  // constrain an instance still has to appear above, so a schema that grows a
  // real one keeps failing loudly rather than validating vacuously.
  $schema?: string;
  $id?: string;
  title?: string;
  description?: string;
}

const KNOWN_KEYWORDS = new Set([
  // Constraining keywords — each one is actually enforced below.
  "type", "enum", "const", "required", "properties", "additionalProperties",
  "items", "uniqueItems",
  // Annotations and envelope keys — see the note on the interface above.
  "$schema", "$id", "title", "description",
]);

function typeOf(value: Json): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value; // "object" | "string" | "boolean" | "number"
}

function matchesType(value: Json, type: string): boolean {
  if (type === "object") return typeOf(value) === "object";
  return typeOf(value) === type;
}

export function validateAgainstSchema(
  value: Json,
  schema: Schema,
  path = "$",
): string[] {
  const errors: string[] = [];

  for (const kw of Object.keys(schema)) {
    if (!KNOWN_KEYWORDS.has(kw)) {
      throw new Error(
        `validate-against-schema: unsupported keyword "${kw}" at ${path} — ` +
          `extend the validator before relying on it`,
      );
    }
  }

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => matchesType(value, t))) {
      errors.push(`${path}: expected type ${types.join("|")}, got ${typeOf(value)}`);
      return errors; // type mismatch — deeper checks are meaningless
    }
  }

  if (schema.enum !== undefined) {
    if (!schema.enum.some((e) => e === value)) {
      errors.push(`${path}: value ${JSON.stringify(value)} not in enum`);
    }
  }

  if (schema.const !== undefined) {
    if (value !== schema.const) {
      errors.push(`${path}: value ${JSON.stringify(value)} !== const ${JSON.stringify(schema.const)}`);
    }
  }

  if (typeOf(value) === "object") {
    const obj = value as Record<string, Json>;
    for (const req of schema.required ?? []) {
      if (!(req in obj)) errors.push(`${path}: missing required property "${req}"`);
    }
    if (schema.additionalProperties === false && schema.properties) {
      for (const key of Object.keys(obj)) {
        if (!(key in schema.properties)) {
          errors.push(`${path}: additional property "${key}" not allowed`);
        }
      }
    }
    if (schema.properties) {
      for (const [key, sub] of Object.entries(schema.properties)) {
        if (key in obj) {
          errors.push(...validateAgainstSchema(obj[key], sub, `${path}.${key}`));
        }
      }
    }
  }

  if (typeOf(value) === "array" && schema.items) {
    const arr = value as Json[];
    arr.forEach((item, i) => {
      errors.push(...validateAgainstSchema(item, schema.items!, `${path}[${i}]`));
    });
    if (schema.uniqueItems) {
      const seen = new Set(arr.map((x) => JSON.stringify(x)));
      if (seen.size !== arr.length) errors.push(`${path}: items are not unique`);
    }
  }

  return errors;
}
