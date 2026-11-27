/**
 * Equivalence of the two crypto backends.
 *
 * The browser path is only trustworthy if it computes the SAME answers as the
 * audited Node path — so this asserts it primitive by primitive rather than
 * assuming it. Every case runs through BOTH providers and compares.
 *
 * Signatures are produced with `node:crypto` (the reference signer's behavior)
 * and then verified by both backends, which is the direction that matters: a
 * browser must accept exactly the artifacts a Node verifier accepts, and reject
 * exactly the ones it rejects.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, sign, createHash } from "node:crypto";

import { nodeProvider } from "./node.js";
import { webProvider } from "./web.js";
import { toHex, utf8Bytes } from "./bytes.js";

const PROVIDERS = [
  ["node", nodeProvider],
  ["web", webProvider],
] as const;

// ── SHA3-256 ────────────────────────────────────────────────────────────────

test("sha3-256: both backends agree, and match node:crypto", () => {
  const cases: Uint8Array[] = [
    new Uint8Array(0),
    utf8Bytes("certcrypt"),
    utf8Bytes("a".repeat(1000)),
    new Uint8Array(4096).map((_, i) => i % 251),
    // 1 MiB — a commitment over material large enough to matter in a browser.
    new Uint8Array(1024 * 1024).map((_, i) => i % 7),
  ];

  for (const input of cases) {
    const reference = createHash("sha3-256").update(input).digest("hex");
    for (const [name, provider] of PROVIDERS) {
      assert.equal(
        toHex(provider.sha3_256(input)),
        reference,
        `${name} backend digest differs at length ${input.length}`
      );
    }
  }
});

test("sha3-256 streaming: chunked equals one-shot, at every boundary", () => {
  // The property that makes streaming safe to use at all: a digest assembled from chunks
  // must equal the digest of the whole buffer. Chunk sizes are chosen to straddle SHA3-256's
  // 136-byte rate — a boundary landing mid-block is exactly where a naive implementation
  // would drift, and it would drift SILENTLY, producing a wrong commitment rather than an
  // error.
  const inputs: Uint8Array[] = [
    new Uint8Array(0),
    utf8Bytes("certcrypt"),
    new Uint8Array(135).map((_, i) => i % 251), // one below the rate
    new Uint8Array(136).map((_, i) => i % 251), // exactly the rate
    new Uint8Array(137).map((_, i) => i % 251), // one above
    new Uint8Array(1024 * 1024 + 7).map((_, i) => i % 13) // 1 MiB, deliberately not aligned
  ];
  const chunkSizes = [1, 7, 64, 135, 136, 137, 4096, 1024 * 1024];

  for (const input of inputs) {
    const reference = createHash("sha3-256").update(input).digest("hex");
    for (const [name, provider] of PROVIDERS) {
      for (const size of chunkSizes) {
        const stream = provider.sha3_256_stream();
        for (let at = 0; at < input.length; at += size) {
          stream.update(input.subarray(at, Math.min(at + size, input.length)));
        }
        assert.equal(
          toHex(stream.digest()),
          reference,
          `${name}: streamed digest differs at length ${input.length}, chunk ${size}`
        );
      }
    }
  }
});

test("sha3-256 streaming: a zero-length update does not change the digest", () => {
  // A chunked reader can legitimately hand over an empty slice — at EOF, or for a
  // zero-length archive member. If that shifted the state, the file would hash differently
  // depending on how it happened to be read.
  for (const [name, provider] of PROVIDERS) {
    const input = utf8Bytes("certcrypt");
    const plain = provider.sha3_256_stream();
    plain.update(input);

    const withEmpties = provider.sha3_256_stream();
    withEmpties.update(new Uint8Array(0));
    withEmpties.update(input.subarray(0, 4));
    withEmpties.update(new Uint8Array(0));
    withEmpties.update(input.subarray(4));
    withEmpties.update(new Uint8Array(0));

    assert.equal(toHex(withEmpties.digest()), toHex(plain.digest()), name);
  }
});

test("sha3-256: the empty-input vector is the known Keccak constant", () => {
  const expected =
    "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
  for (const [name, provider] of PROVIDERS) {
    assert.equal(toHex(provider.sha3_256(new Uint8Array(0))), expected, name);
  }
});

// ── Ed25519 ─────────────────────────────────────────────────────────────────

test("ed25519: both backends accept valid and reject tampered signatures", () => {
  for (let i = 0; i < 10; i++) {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const message = utf8Bytes(`certcrypt-ed25519-${i}`);
    const signature = new Uint8Array(sign(null, message, privateKey));

    const spki = new Uint8Array(
      publicKey.export({ type: "spki", format: "der" }) as Buffer
    );
    const raw = spki.subarray(spki.length - 32);

    const tampered = new Uint8Array(signature);
    tampered[0] ^= 0x01;

    for (const [name, provider] of PROVIDERS) {
      // Both key encodings must be accepted, and agree.
      for (const [form, key] of [
        ["raw", raw],
        ["spki", spki],
      ] as const) {
        assert.equal(
          provider.verifyEd25519(key, message, signature),
          true,
          `${name}/${form} rejected a valid signature`
        );
      }
      assert.equal(
        provider.verifyEd25519(raw, message, tampered),
        false,
        `${name} accepted a tampered signature`
      );
      assert.equal(
        provider.verifyEd25519(raw, utf8Bytes("other message"), signature),
        false,
        `${name} accepted a signature over the wrong message`
      );
    }
  }
});

// ── ECDSA P-256 over SHA3-256 ───────────────────────────────────────────────

const P256_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

function sIsHigh(signature: Uint8Array): boolean {
  let s = 0n;
  for (const b of signature.subarray(32, 64)) s = (s << 8n) | BigInt(b);
  return s > P256_N >> 1n;
}

test("p256/sha3: both backends agree on node-produced signatures", () => {
  // Enough iterations that both low-s and high-s signatures occur: node does not
  // normalize s, and the two backends must agree on BOTH — the low-s rule is
  // enforced a layer up, in ecdsa-p256.ts, not inside a backend.
  let lowSeen = 0;
  let highSeen = 0;

  for (let i = 0; i < 30; i++) {
    const { publicKey, privateKey } = generateKeyPairSync("ec", {
      namedCurve: "P-256",
    });
    const message = utf8Bytes(`certcrypt-p256-${i}`);
    const signature = new Uint8Array(
      sign("sha3-256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })
    );
    sIsHigh(signature) ? highSeen++ : lowSeen++;

    const spki = new Uint8Array(
      publicKey.export({ type: "spki", format: "der" }) as Buffer
    );
    const sec1 = spki.subarray(spki.length - 65);

    const tampered = new Uint8Array(signature);
    tampered[0] ^= 0x01;

    for (const [name, provider] of PROVIDERS) {
      for (const [form, key] of [
        ["sec1", sec1],
        ["spki", spki],
      ] as const) {
        assert.equal(
          provider.verifyEcdsaP256Sha3(key, message, signature),
          true,
          `${name}/${form} rejected a valid signature (high-s: ${sIsHigh(signature)})`
        );
      }
      assert.equal(
        provider.verifyEcdsaP256Sha3(sec1, message, tampered),
        false,
        `${name} accepted a tampered signature`
      );
      assert.equal(
        provider.verifyEcdsaP256Sha3(sec1, utf8Bytes("other"), signature),
        false,
        `${name} accepted a signature over the wrong message`
      );
    }
  }

  // Guards the guard: if node ever started normalizing s, this test would stop
  // covering the high-s path and silently weaken.
  assert.ok(lowSeen > 0, "expected at least one low-s signature");
  assert.ok(highSeen > 0, "expected at least one high-s signature");
});

test("p256/sha3: the digest is SHA3-256, not SHA-2", () => {
  // A backend that quietly used SHA-256 would reject every real signature. This
  // pins the distinction rather than trusting the parameter name.
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const message = utf8Bytes("certcrypt-digest-discipline");
  const spki = new Uint8Array(
    publicKey.export({ type: "spki", format: "der" }) as Buffer
  );
  const sec1 = spki.subarray(spki.length - 65);

  const sha3Sig = new Uint8Array(
    sign("sha3-256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })
  );
  const sha2Sig = new Uint8Array(
    sign("sha256", message, { key: privateKey, dsaEncoding: "ieee-p1363" })
  );

  for (const [name, provider] of PROVIDERS) {
    assert.equal(
      provider.verifyEcdsaP256Sha3(sec1, message, sha3Sig),
      true,
      `${name} rejected a SHA3-256 signature`
    );
    assert.equal(
      provider.verifyEcdsaP256Sha3(sec1, message, sha2Sig),
      false,
      `${name} accepted a SHA-2 signature under a SHA3-256 contract`
    );
  }
});

// ── Malformed input ─────────────────────────────────────────────────────────

test("both backends reject malformed key material identically", () => {
  const message = utf8Bytes("certcrypt");
  const signature = new Uint8Array(64);

  for (const [name, provider] of PROVIDERS) {
    // Wrong-length keys throw on both backends (malformed key material is an
    // error, not a false verdict).
    assert.throws(
      () => provider.verifyEd25519(new Uint8Array(31), message, signature),
      /Ed25519 public key/,
      `${name} accepted a 31-byte Ed25519 key`
    );
    assert.throws(
      () => provider.verifyEcdsaP256Sha3(new Uint8Array(64), message, signature),
      /P-256 public key|ECDSA-P256 public key/,
      `${name} accepted a 64-byte P-256 key`
    );
  }
});

test("an all-zero signature is a false verdict, never a throw", () => {
  // Adversary-controlled signature bytes must not be able to raise.
  const { publicKey } = generateKeyPairSync("ed25519");
  const spki = new Uint8Array(
    publicKey.export({ type: "spki", format: "der" }) as Buffer
  );
  const raw = spki.subarray(spki.length - 32);

  for (const [name, provider] of PROVIDERS) {
    assert.equal(
      provider.verifyEd25519(raw, utf8Bytes("m"), new Uint8Array(64)),
      false,
      `${name} did not reject an all-zero signature`
    );
  }
});
