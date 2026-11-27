/**
 * Composite signature verification (CERTCRYPT Composite Signature Profile).
 *
 * The permanent trust chain (emission certificate, system-foundation root,
 * Proof of Independence, Level-1 binding) signs as a COMPOSITE: every component
 * signs the SAME domain-separated message M', and the composite verifies iff ALL
 * components verify (AND). Binding the composite profile id into M' stops a
 * component being lifted out and replayed under another profile (anti-stripping,
 * anti cross-profile).
 *
 *   M' = ASCII(domain_prefix) || 0x00 || ASCII(composite_alg_id) || 0x00
 *        || ASCII(payload_canon_digest_hex)
 *
 * domain_prefix = "CERTCRYPT-Composite-Signature-v1" (no year). The 0x00
 * separators make the field split injective.
 *
 * Canonical profile `certcrypt-composite-p256-mldsa65-v1`: ECDSA-P256-SHA3-256
 * (classical, first) + ML-DSA-65 (PQC). Additional profile
 * `certcrypt-composite-ed25519-mldsa65-v1` swaps the classical for Ed25519.
 *
 * EXACT LAYOUT: the profile fixes the wire object completely — `{alg, mode,
 * signatures}`, exactly two components in the profile's order (classical first),
 * each with exactly its members, the ECDSA component with `encoding:"raw-rs-64"`
 * and `low_s:true` — and one encoding per public key: P-256 as a 65-byte SEC1
 * uncompressed point, Ed25519 as its raw 32 bytes, ML-DSA-65 as its 1952-byte
 * pkEncode. Anything else is malformed and never reaches the cryptography, so two
 * byte forms of one signature or one key can never both be accepted.
 *
 * COMPOSITE-ONLY: `verifyComposite` is the only signature verdict. The per-component
 * verifiers (`verifyEcdsaP256Signature`, `verifyEd25519Signature`,
 * `verifyMlDsa65Signature`) are primitives, never verdicts. Mirrors the reference
 * producer and the conformance generator; M' bytes are
 * load-bearing cross-language. Fail-closed: the ML-DSA (PQC) component is the
 * post-quantum floor and can never be skipped.
 */
import { verifyEcdsaP256Signature } from "./ecdsa-p256.js";
import { verifyEd25519Signature } from "./ed25519.js";
import { verifyMlDsa65Signature } from "./ml-dsa.js";
import { strictBase64Decode } from "./provider/bytes.js";

export const COMPOSITE_DOMAIN_PREFIX = "CERTCRYPT-Composite-Signature-v1";

export const PROFILE_P256_MLDSA65 = "certcrypt-composite-p256-mldsa65-v1";
export const PROFILE_ED25519_MLDSA65 = "certcrypt-composite-ed25519-mldsa65-v1";

export const ALG_ECDSA_P256 = "ECDSA-P256-SHA3-256";
export const ALG_ED25519 = "Ed25519";
export const ALG_MLDSA65 = "ML-DSA-65";

/** One detached component signature (a `signatures[]` entry). */
export interface ComponentSignature {
  alg: string;
  encoding?: string;
  low_s?: boolean;
  sig_b64: string;
}

/** The composite signature wire object. */
export interface CompositeSignatureWire {
  alg: string;
  mode: string;
  signatures: ComponentSignature[];
}

/** Public keys for composite verification (classical + the PQC ML-DSA key). */
export interface CompositePublicKeys {
  /** Classical pubkey: P-256 SEC1 uncompressed (65 bytes), or Ed25519 raw (32 bytes), base64. */
  classicalPubB64: string;
  /** ML-DSA-65 pkEncode (1952 bytes), base64. */
  mldsaPubB64: string;
}

/** FIPS 204 ML-DSA-65 public-key length. */
export const MLDSA65_PUBLIC_KEY_LEN = 1952;
/** SEC1 uncompressed P-256 point length (0x04 || X || Y). */
export const P256_SEC1_UNCOMPRESSED_LEN = 65;
/** RFC 8032 Ed25519 public-key length. */
export const ED25519_PUBLIC_KEY_LEN = 32;

interface ComponentSlot {
  alg: string;
  members: readonly string[];
  /** Members whose value is fixed by the profile. */
  fixed?: Readonly<Record<string, unknown>>;
}

const ECDSA_SLOT: ComponentSlot = {
  alg: ALG_ECDSA_P256,
  members: ["alg", "encoding", "low_s", "sig_b64"],
  fixed: { encoding: "raw-rs-64", low_s: true },
};
const ED25519_SLOT: ComponentSlot = { alg: ALG_ED25519, members: ["alg", "sig_b64"] };
const MLDSA_SLOT: ComponentSlot = { alg: ALG_MLDSA65, members: ["alg", "sig_b64"] };

/** Each registered profile's exact component layout, in wire order. */
const PROFILE_LAYOUT: Readonly<Record<string, readonly ComponentSlot[]>> = {
  [PROFILE_P256_MLDSA65]: [ECDSA_SLOT, MLDSA_SLOT],
  [PROFILE_ED25519_MLDSA65]: [ED25519_SLOT, MLDSA_SLOT],
};

const WIRE_MEMBERS = ["alg", "mode", "signatures"];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function hasExactly(obj: Record<string, unknown>, members: readonly string[]): boolean {
  const keys = Object.keys(obj);
  return keys.length === members.length && members.every((m) => Object.hasOwn(obj, m));
}

/**
 * Why `sig` is not a well-formed composite under `compositeAlgId` with `keys`,
 * or null when its layout and key encodings are exactly the profile's.
 * Exported so that a carrying artifact can report malformed material as such.
 */
export function compositeLayoutError(
  compositeAlgId: string,
  sig: unknown,
  keys: CompositePublicKeys
): string | null {
  const layout = PROFILE_LAYOUT[compositeAlgId];
  if (!layout) return `unsupported composite profile: ${compositeAlgId}`;
  if (!isPlainObject(sig) || !hasExactly(sig, WIRE_MEMBERS)) {
    return `signature must be an object with exactly ${WIRE_MEMBERS.join(", ")}`;
  }
  if (sig.alg !== compositeAlgId) {
    return `profile mismatch: ${String(sig.alg)} != ${compositeAlgId}`;
  }
  if (sig.mode !== "AND") return `unsupported composite mode: ${String(sig.mode)}`;
  const comps = sig.signatures;
  if (!Array.isArray(comps) || comps.length !== layout.length) {
    return `signatures must hold exactly the ${layout.length} components of the profile`;
  }
  for (let i = 0; i < layout.length; i++) {
    const slot = layout[i];
    const c: unknown = comps[i];
    if (!isPlainObject(c) || c.alg !== slot.alg) {
      return `component ${i} must be ${slot.alg} (the profile fixes the order)`;
    }
    if (!hasExactly(c, slot.members)) {
      return `component ${i} (${slot.alg}) must carry exactly ${slot.members.join(", ")}`;
    }
    for (const [member, value] of Object.entries(slot.fixed ?? {})) {
      if (c[member] !== value) {
        return `component ${i} (${slot.alg}) ${member} must be ${JSON.stringify(value)}`;
      }
    }
    if (typeof c.sig_b64 !== "string") return `component ${i} sig_b64 must be a string`;
  }

  const keyLen = (b64: string, field: string): number | string => {
    try {
      return strictBase64Decode(b64, field).length;
    } catch (err: unknown) {
      return err instanceof Error ? err.message : String(err);
    }
  };
  const classical = layout[0].alg;
  const cBytes = (() => {
    try {
      return strictBase64Decode(keys.classicalPubB64, "classical_public_key");
    } catch (err: unknown) {
      return err instanceof Error ? err.message : String(err);
    }
  })();
  if (typeof cBytes === "string") return cBytes;
  if (classical === ALG_ECDSA_P256) {
    if (cBytes.length !== P256_SEC1_UNCOMPRESSED_LEN || cBytes[0] !== 0x04) {
      return "classical public key must be a SEC1 uncompressed P-256 point (65 bytes, 0x04)";
    }
  } else if (cBytes.length !== ED25519_PUBLIC_KEY_LEN) {
    return "classical public key must be a raw Ed25519 key (32 bytes)";
  }
  const mLen = keyLen(keys.mldsaPubB64, "pqc_public_key");
  if (typeof mLen === "string") return mLen;
  if (mLen !== MLDSA65_PUBLIC_KEY_LEN) {
    return `ML-DSA-65 public key must be ${MLDSA65_PUBLIC_KEY_LEN} bytes, got ${mLen}`;
  }
  return null;
}

/**
 * Build the domain-separated message M' every component signs.
 *
 * @param compositeAlgId the PROFILE id (bound in → anti cross-profile).
 * @param payloadCanonDigestHex lowercase-hex SHA3-256(JCS(payload)).
 */
export function compositeMPrime(
  compositeAlgId: string,
  payloadCanonDigestHex: string
): Uint8Array {
  const enc = new TextEncoder();
  const prefix = enc.encode(COMPOSITE_DOMAIN_PREFIX);
  const alg = enc.encode(compositeAlgId);
  const digest = enc.encode(payloadCanonDigestHex);
  const out = new Uint8Array(prefix.length + 1 + alg.length + 1 + digest.length);
  let o = 0;
  out.set(prefix, o); o += prefix.length;
  out[o++] = 0x00;
  out.set(alg, o); o += alg.length;
  out[o++] = 0x00;
  out.set(digest, o);
  return out;
}

export interface CompositeVerifyResult {
  /** True iff ALL components verified (AND) and the PQC floor was present. */
  valid: boolean;
  /**
   * Set when the signature or a key is malformed for the profile (layout,
   * member set, fixed values, key encoding): a structural defect, distinct from
   * a well-formed signature that does not verify.
   */
  malformed: string | null;
  classical: { alg: string | null; passed: boolean; reason: string | null };
  mldsa: { performed: boolean; passed: boolean | null; reason: string | null };
}

/**
 * Verify a composite signature over `payloadCanonDigestHex` under
 * `compositeAlgId` — the profile the CONTEXT requires, never the one the
 * signature declares. The layout and key encodings must be exactly the
 * profile's; then AND with fail-closed: ALL components must verify AND the
 * ML-DSA component MUST pass.
 */
export function verifyComposite(
  compositeAlgId: string,
  payloadCanonDigestHex: string,
  sig: CompositeSignatureWire,
  keys: CompositePublicKeys
): CompositeVerifyResult {
  const layoutError = compositeLayoutError(compositeAlgId, sig, keys);
  if (layoutError) {
    return {
      valid: false,
      malformed: layoutError,
      classical: { alg: null, passed: false, reason: `malformed: ${layoutError}` },
      mldsa: { performed: false, passed: null, reason: `malformed: ${layoutError}` },
    };
  }

  const mPrime = compositeMPrime(compositeAlgId, payloadCanonDigestHex);
  const [classicalComp, mldsaComp] = sig.signatures;

  // Classical component.
  let classical: { alg: string; passed: boolean; reason: string | null };
  try {
    const ok =
      classicalComp.alg === ALG_ECDSA_P256
        ? verifyEcdsaP256Signature(keys.classicalPubB64, mPrime, classicalComp.sig_b64)
        : verifyEd25519Signature(keys.classicalPubB64, mPrime, classicalComp.sig_b64);
    classical = { alg: classicalComp.alg, passed: ok, reason: ok ? null : "verification_failed" };
  } catch (err: unknown) {
    classical = {
      alg: classicalComp.alg,
      passed: false,
      reason: err instanceof Error ? err.message : String(err),
    };
  }

  // ML-DSA-65 component (the post-quantum floor).
  const mldsa = verifyMlDsa65Signature(keys.mldsaPubB64, mPrime, mldsaComp.sig_b64);

  const valid = classical.passed && mldsa.performed === true && mldsa.passed === true;
  return { valid, malformed: null, classical, mldsa };
}
