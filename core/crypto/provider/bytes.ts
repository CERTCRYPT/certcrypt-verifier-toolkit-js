/**
 * Runtime-neutral byte helpers.
 *
 * `Buffer` is a Node built-in, so every use of it pins the toolkit to Node. The
 * verifier only ever needs three operations on raw bytes — strict base64 decode,
 * hex encode, and concatenation — and all three are expressible over Uint8Array
 * alone. Keeping them here means the verification core never names `Buffer`.
 *
 * Strictness is deliberate: base64 decoding rejects anything outside RFC 4648
 * rather than salvaging it, because a verifier that accepts sloppy encodings
 * accepts artifacts a conformant implementation would reject.
 */

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Decode RFC 4648 base64, strictly. Throws (never returns partial output) on any
 * character outside the alphabet, on a length that is not a multiple of 4, on
 * empty input, and on non-canonical trailing bits (RFC 4648 §3.5): the unused
 * low bits of the last character before the padding must be zero, so one byte
 * string has exactly one accepted spelling.
 *
 * @param b64        the base64 text
 * @param fieldName  named in the error, so a failure says which field was bad
 */
export function strictBase64Decode(b64: string, fieldName: string): Uint8Array {
  if (!b64 || b64.length === 0) {
    throw new Error(`${fieldName}: empty base64 input`);
  }
  if (!BASE64_RE.test(b64)) {
    throw new Error(
      `${fieldName}: invalid RFC 4648 base64 — contains non-alphabet characters`
    );
  }
  if (b64.length % 4 !== 0) {
    throw new Error(
      `${fieldName}: invalid RFC 4648 base64 — length is not a multiple of 4`
    );
  }

  // Padding may only be the final one or two characters; "=" anywhere else is
  // malformed even though the character is in the regex above.
  const padIndex = b64.indexOf("=");
  if (padIndex !== -1 && padIndex < b64.length - 2) {
    throw new Error(
      `${fieldName}: invalid RFC 4648 base64 — padding before end of input`
    );
  }

  const padding = b64.endsWith("==") ? 2 : b64.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((b64.length / 4) * 3 - padding);
  let o = 0;

  for (let i = 0; i < b64.length; i += 4) {
    const c0 = BASE64_ALPHABET.indexOf(b64[i]);
    const c1 = BASE64_ALPHABET.indexOf(b64[i + 1]);
    const c2 = b64[i + 2] === "=" ? 0 : BASE64_ALPHABET.indexOf(b64[i + 2]);
    const c3 = b64[i + 3] === "=" ? 0 : BASE64_ALPHABET.indexOf(b64[i + 3]);
    if (c0 < 0 || c1 < 0 || c2 < 0 || c3 < 0) {
      throw new Error(
        `${fieldName}: invalid RFC 4648 base64 — contains non-alphabet characters`
      );
    }
    const last = i + 4 === b64.length;
    if (last && ((padding === 2 && (c1 & 0x0f) !== 0) || (padding === 1 && (c2 & 0x03) !== 0))) {
      throw new Error(
        `${fieldName}: invalid RFC 4648 base64 — non-canonical trailing bits`
      );
    }
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    if (o < out.length) out[o++] = (triple >> 16) & 0xff;
    if (o < out.length) out[o++] = (triple >> 8) & 0xff;
    if (o < out.length) out[o++] = triple & 0xff;
  }

  return out;
}

/** Lowercase hex encoding — the form every digest in the spec is written in. */
export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/** Decode lowercase or uppercase hex. Throws on odd length or non-hex digits. */
export function fromHex(hex: string, fieldName = "hex"): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error(`${fieldName}: hex length is not even`);
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`${fieldName}: invalid hex digit`);
    }
    out[i] = byte;
  }
  return out;
}

/** Concatenate byte runs into one buffer. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

/** UTF-8 encode. `TextEncoder` is standard in Node >= 11 and every browser. */
export function utf8Bytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}
