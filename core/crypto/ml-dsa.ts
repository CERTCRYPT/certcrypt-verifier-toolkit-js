/**
 * ML-DSA-65 (FIPS 204) signature verification via @noble/post-quantum.
 *
 * @noble/post-quantum is an optionalDependency for PACKAGING reasons only: a
 * runtime that cannot install it should still be able to install the toolkit.
 * It is operationally REQUIRED. ML-DSA-65 is the post-quantum floor of every
 * composite signature (composite.ts), so if the backend is absent this returns
 * performed:false / unsupported_runtime, and verify-issued.ts converts that into
 * a hard UNSUPPORTED verdict. The verifier refuses rather than falling back to
 * the classical component alone.
 */

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

type MlDsa65Module = {
  verify(sig: Uint8Array, msg: Uint8Array, publicKey: Uint8Array): boolean;
};

let _mlDsa65: MlDsa65Module | null | undefined = undefined; // undefined = not yet checked

/**
 * Try to load the ML-DSA-65 backend.
 * Returns the module if available, null if not installed.
 */
async function loadMlDsa65(): Promise<MlDsa65Module | null> {
  if (_mlDsa65 !== undefined) return _mlDsa65;
  try {
    const mod = await import("@noble/post-quantum/ml-dsa.js");
    _mlDsa65 = mod.ml_dsa65 as MlDsa65Module;
    return _mlDsa65;
  } catch {
    _mlDsa65 = null;
    return null;
  }
}

/**
 * Synchronous check — must call loadMlDsa65() first.
 */
function getMlDsa65(): MlDsa65Module | null {
  return _mlDsa65 ?? null;
}

/**
 * Initialize the ML-DSA-65 backend (call once at startup).
 */
export async function initMlDsa65(): Promise<boolean> {
  const mod = await loadMlDsa65();
  return mod !== null;
}

/**
 * Verify an ML-DSA-65 signature.
 *
 * @returns { performed, passed, reason }
 */
export function verifyMlDsa65Signature(
  publicKeyB64: string,
  payloadBytes: Uint8Array,
  signatureB64: string
): { performed: boolean; passed: boolean | null; reason: string | null } {
  const backend = getMlDsa65();
  if (!backend) {
    return { performed: false, passed: null, reason: "unsupported_runtime" };
  }

  let pubKeyBytes: Uint8Array;
  try {
    pubKeyBytes = strictBase64Decode(publicKeyB64, "pqc_public_key");
  } catch (err: unknown) {
    return {
      performed: false,
      passed: null,
      reason: `malformed_pqc_material: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  let sigBytes: Uint8Array;
  try {
    sigBytes = strictBase64Decode(signatureB64, "pqc_signature");
  } catch (err: unknown) {
    return {
      performed: false,
      passed: null,
      reason: `malformed_pqc_material: ${err instanceof Error ? err.message : String(err)}`,
    };
  }

  try {
    const valid = backend.verify(sigBytes, payloadBytes, pubKeyBytes);
    return {
      performed: true,
      passed: valid,
      reason: valid ? null : "verification_failed",
    };
  } catch (err: unknown) {
    return {
      performed: true,
      passed: false,
      reason: `verification_error: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

function strictBase64Decode(b64: string, fieldName: string): Uint8Array {
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
  return new Uint8Array(Buffer.from(b64, "base64"));
}
