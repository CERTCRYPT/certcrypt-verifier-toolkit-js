/**
 * SHA3-256 — the digest under every commitment in the spec.
 *
 * Delegates to the active crypto provider so the same code runs on Node
 * (`node:crypto`) and in a browser (`@noble/hashes`). Note WebCrypto cannot
 * serve this: it has no SHA-3 at any digest length.
 */
import { getCryptoProvider } from "./provider/index.js";
import { toHex, utf8Bytes } from "./provider/bytes.js";

export function digestHexBytes(data: Uint8Array): string {
  return toHex(getCryptoProvider().sha3_256(data));
}

export function digestHexText(text: string): string {
  return toHex(getCryptoProvider().sha3_256(utf8Bytes(text)));
}

/**
 * Incremental SHA3-256 over data the caller feeds in pieces.
 *
 * For material too large to hold in one buffer: read it in chunks, `update()` each, then
 * `digestHex()`. The result equals `digestHexBytes()` over the concatenation — pinned in
 * `provider.equivalence.test.ts` at chunk sizes straddling the 136-byte rate.
 *
 * Only meaningful where canonical_bytes ARE the input bytes, i.e. `subject.binary/1`. Every
 * other subject profile transforms the material first, and none of those transformations is
 * chunk-local.
 */
export function digestHexStream(): {
  update(chunk: Uint8Array): void;
  digestHex(): string;
} {
  const stream = getCryptoProvider().sha3_256_stream();
  return {
    update: (chunk) => stream.update(chunk),
    digestHex: () => toHex(stream.digest())
  };
}

export function digestBytes(data: Uint8Array): Uint8Array {
  return getCryptoProvider().sha3_256(data);
}
