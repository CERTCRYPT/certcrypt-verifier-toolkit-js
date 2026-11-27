/**
 * Tests for the ECDSA P-256 primitive (classical component of the composite).
 *
 * The verifier toolkit does not sign; these tests generate keypairs and
 * signatures with node:crypto to exercise verify(). Covers: valid low-s,
 * tamper, high-s rejection (normative anti-malleability), bad lengths, SEC1
 * uncompressed + compressed + SPKI DER public-key forms.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign, type KeyObject } from "node:crypto";
import { verifyEcdsaP256Signature } from "./ecdsa-p256.js";

const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const P256_HALF_N = P256_N >> 1n;

function b64(b: Uint8Array | Buffer): string {
  return Buffer.from(b).toString("base64");
}
function beBytes(x: bigint, len = 32): Buffer {
  const out = Buffer.alloc(len);
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}
function sToBig(sig: Buffer): bigint {
  let acc = 0n;
  for (const byte of sig.subarray(32, 64)) acc = (acc << 8n) | BigInt(byte);
  return acc;
}

function freshKey() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  // Uncompressed SEC1 (65B) and compressed (33B) via JWK round-trip.
  const jwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  const x = Buffer.from(jwk.x!, "base64url");
  const y = Buffer.from(jwk.y!, "base64url");
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);
  const yOdd = (y[y.length - 1] & 1) === 1;
  const compressed = Buffer.concat([Buffer.from([yOdd ? 0x03 : 0x02]), x]);
  const spkiDer = publicKey.export({ format: "der", type: "spki" }) as Buffer;
  return { privateKey, uncompressed, compressed, spkiDer };
}

/** Sign over SHA3-256, low-s (flip to n-s if node produced high-s). */
function signLowS(privateKey: KeyObject, msg: Buffer): Buffer {
  // Match the verifier: node hashes with SHA3-256 internally.
  const sig = cryptoSign("sha3-256", msg, { key: privateKey, dsaEncoding: "ieee-p1363" }) as Buffer;
  if (sToBig(sig) > P256_HALF_N) {
    const sLow = P256_N - sToBig(sig);
    return Buffer.concat([sig.subarray(0, 32), beBytes(sLow)]);
  }
  return sig;
}

test("verifies a valid low-s signature (SEC1 uncompressed pubkey)", () => {
  const { privateKey, uncompressed } = freshKey();
  const msg = Buffer.from("the message that is signed (M')");
  const sig = signLowS(privateKey, msg);
  assert.equal(verifyEcdsaP256Signature(b64(uncompressed), msg, b64(sig)), true);
});

test("verifies with SPKI DER and compressed SEC1 pubkey forms", () => {
  const { privateKey, compressed, spkiDer } = freshKey();
  const msg = Buffer.from("multi-encoding");
  const sig = signLowS(privateKey, msg);
  assert.equal(verifyEcdsaP256Signature(b64(spkiDer), msg, b64(sig)), true, "SPKI DER");
  assert.equal(verifyEcdsaP256Signature(b64(compressed), msg, b64(sig)), true, "compressed SEC1");
});

test("rejects a tampered message", () => {
  const { privateKey, uncompressed } = freshKey();
  const sig = signLowS(privateKey, Buffer.from("original"));
  assert.equal(verifyEcdsaP256Signature(b64(uncompressed), Buffer.from("tampered"), b64(sig)), false);
});

test("REJECTS a high-s signature (normative anti-malleability, not normalized)", () => {
  const { privateKey, uncompressed } = freshKey();
  const msg = Buffer.from("low-s only");
  const low = signLowS(privateKey, msg);
  // Build the malleable high-s twin: s' = n - s. It is a mathematically valid
  // ECDSA signature, but the profile MUST reject it.
  const highS = P256_N - sToBig(low);
  assert.ok(highS > P256_HALF_N, "twin must be high-s");
  const highSig = Buffer.concat([low.subarray(0, 32), beBytes(highS)]);
  assert.equal(verifyEcdsaP256Signature(b64(uncompressed), msg, b64(highSig)), false);
});

test("rejects a signature of wrong length (not raw-rs-64)", () => {
  const { uncompressed } = freshKey();
  assert.throws(
    () => verifyEcdsaP256Signature(b64(uncompressed), Buffer.from("x"), b64(Buffer.alloc(70))),
    /raw-rs-64/
  );
});

test("rejects r or s equal to zero", () => {
  const { uncompressed } = freshKey();
  const msg = Buffer.from("zeros");
  const zeros = Buffer.alloc(64); // r=0, s=0
  assert.equal(verifyEcdsaP256Signature(b64(uncompressed), msg, b64(zeros)), false);
});
