import type { LoadedArtifacts, SystemDomainConfig, BaseCertificate } from "../types/index.js";
import { ResultBuilder } from "../result/builder.js";
import { jcsCanonicalizeBytes } from "../crypto/jcs.js";
import { digestHexBytes, digestHexText } from "../crypto/digest.js";
import { verifyComposite } from "../crypto/composite.js";
import { verifyOriginalMaterial } from "./verify-original-material.js";

const HEX64_RE = /^[0-9a-f]{64}$/;
const SUBJECT_PROFILE_RE = /^subject\.[a-z0-9][a-z0-9_.-]{0,63}\/[1-9][0-9]*$/;
/** CCSP/1 §7.3.1: `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, UTC, uppercase `T` and `Z`. */
const ISSUED_AT_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?Z$/;
/** CCSP/1 §3 ASCII token: printable US-ASCII without SPACE. */
const ASCII_TOKEN_RE = /^[\x21-\x7e]+$/;

const TOP_LEVEL_REQUIRED = ["schema", "payload", "signatures"];
const TOP_LEVEL_OPTIONAL = ["metadata", "payload_canon_digest_hex", "extensions"];
const PAYLOAD_RESERVED = ["consensus", "economics"];
const ANCHOR_REQUIRED = ["issued_at", "nonce_hex", "subjects"];
const ANCHOR_OPTIONAL = ["root_id"];
const ANCHOR_RESERVED = ["claim", "economic_policy_id"];
const ISSUER_REQUIRED = ["role", "alg", "mode", "sig_target", "signatures", "signer"];
const ISSUER_OPTIONAL = ["kid"];
const SIGNER_MEMBERS = ["id", "pub_p256_b64", "pub_mldsa_b64"];

/**
 * CCSP/1 §7.4.2: the two component objects, in order, each closed. The signer
 * carries a P-256 key, so the classical component is ECDSA P-256.
 */
const COMPONENTS: ReadonlyArray<{ alg: string; members: string[] }> = [
  { alg: "ECDSA-P256-SHA3-256", members: ["alg", "encoding", "low_s", "sig_b64"] },
  { alg: "ML-DSA-65", members: ["alg", "sig_b64"] },
];

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Members of `obj` outside `allowed`. */
function extraMembers(obj: Record<string, unknown>, allowed: string[]): string[] {
  return Object.keys(obj).filter((k) => !allowed.includes(k));
}

/** A real calendar instant in the CCSP/1 `issued_at` form. */
function isValidIssuedAt(v: unknown): boolean {
  if (typeof v !== "string") return false;
  const m = ISSUED_AT_RE.exec(v);
  if (!m) return false;
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || h > 23 || mi > 59 || se > 59 || d < 1) return false;
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  return d <= daysInMonth;
}

/**
 * A component signature/key that is malformed (bad base64, wrong length) is a
 * STRUCTURAL defect (→ REJECTED), distinct from a well-formed signature that
 * fails to verify (→ ISSUED_INVALID). The component verifiers throw on malformed
 * input; we key on the message shape.
 */
function isMalformedReason(reason: string | null): boolean {
  if (!reason) return false;
  return (
    reason.includes("base64") ||
    reason.includes("bytes") ||
    reason.includes("SPKI")
  );
}

/**
 * Verify the Issued path.
 *
 * Per CCSP/1 and CCCP/1:
 * - the envelope, `payload.anchor`, the issuer signature object and its signer
 *   are closed; `payload` is open except for its reserved names
 * - `anchor_commitment_digest_hex`, `system_id` and `rules_version` are
 *   required members of the signed payload
 * - `signatures[]` holds exactly one entry: the composite issuer signature
 *   (P-256 + ML-DSA-65) over M' = domain-separated SHA3-256(JCS(payload))
 * - published digests are recomputed; a mismatch is a structural defect
 */
export function verifyIssued(
  artifacts: LoadedArtifacts,
  config: SystemDomainConfig,
  builder: ResultBuilder
): void {
  const cert = artifacts.baseCertificate;
  if (!cert) {
    builder.fail("BASE_CERTIFICATE_STRUCTURE_VALID", "INCOMPLETE", "base_certificate is null");
    return;
  }

  if (!validateCcspStructure(cert, config, builder)) return;
  builder.pass("BASE_CERTIFICATE_STRUCTURE_VALID");

  if (!verifyAuthenticity(cert, config, builder)) return;

  // Complete verification against original material (verifier-toolkit/1).
  // Opt-in plane: runs only when a subject-material map is supplied; otherwise
  // reported as not performed. The map is loaded by the input layer.
  verifyOriginalMaterial(cert, artifacts.originalMaterial, builder, config.admitted_subject_profiles);
}

/**
 * Validate the CCSP/1 envelope (§6–§9). Every failure is REJECTED, except a
 * `rules_version` this verifier does not evaluate, which is UNSUPPORTED.
 */
function validateCcspStructure(
  cert: BaseCertificate,
  config: SystemDomainConfig,
  builder: ResultBuilder
): boolean {
  const reject = (msg: string): false => {
    builder.fail("BASE_CERTIFICATE_STRUCTURE_VALID", "REJECTED", msg);
    return false;
  };
  const raw = cert as unknown;
  if (!isPlainObject(raw)) return reject("certificate must be a JSON object");

  if (raw.schema !== "certcrypt-certificate") {
    return reject(
      `certificate schema must be "certcrypt-certificate", got ${JSON.stringify(raw.schema ?? null)}`
    );
  }

  // §6: the top level is closed.
  const topExtra = extraMembers(raw, [...TOP_LEVEL_REQUIRED, ...TOP_LEVEL_OPTIONAL]);
  if (topExtra.length > 0) return reject(`top-level members not allowed: ${topExtra.join(", ")}`);
  if ("metadata" in raw && !isPlainObject(raw.metadata)) return reject("metadata must be a JSON object");
  if ("extensions" in raw && !isPlainObject(raw.extensions)) return reject("extensions must be a JSON object");

  const missing: string[] = [];
  const payload = raw.payload;
  if (!isPlainObject(payload)) missing.push("payload");
  if (!Array.isArray(raw.signatures) || raw.signatures.length === 0) missing.push("signatures[]");
  if (missing.length > 0) return reject(`CCSP/1 envelope missing: ${missing.join(", ")}`);
  const p = payload as Record<string, unknown>;

  // §9: reserved payload names.
  const reserved = PAYLOAD_RESERVED.filter((k) => k in p).map((k) => `payload.${k}`);
  if (reserved.length > 0) return reject(`reserved field present: ${reserved.join(", ")}`);

  const anchor = p.anchor;
  if (!isPlainObject(anchor)) return reject("payload.anchor is missing");

  // §7.3.1: the anchor is closed; §9 names two reserved members explicitly.
  const anchorReserved = ANCHOR_RESERVED.filter((k) => k in anchor).map((k) => `payload.anchor.${k}`);
  if (anchorReserved.length > 0) return reject(`reserved field present: ${anchorReserved.join(", ")}`);
  const anchorExtra = extraMembers(anchor, [...ANCHOR_REQUIRED, ...ANCHOR_OPTIONAL]);
  if (anchorExtra.length > 0) return reject(`payload.anchor members not allowed: ${anchorExtra.join(", ")}`);

  if (!isValidIssuedAt(anchor.issued_at)) missing.push("payload.anchor.issued_at (RFC 3339 UTC, Z)");
  if (typeof anchor.nonce_hex !== "string" || !HEX64_RE.test(anchor.nonce_hex))
    missing.push("payload.anchor.nonce_hex");
  if ("root_id" in anchor && (typeof anchor.root_id !== "string" || !HEX64_RE.test(anchor.root_id)))
    missing.push("payload.anchor.root_id (64 lowercase hex)");
  const subjects = anchor.subjects;
  if (!Array.isArray(subjects) || subjects.length === 0) {
    missing.push("payload.anchor.subjects[]");
  } else {
    subjects.forEach((s: unknown, i: number) => {
      if (!isPlainObject(s)) {
        missing.push(`subjects[${i}] (object)`);
        return;
      }
      if (typeof s.profile !== "string" || !SUBJECT_PROFILE_RE.test(s.profile))
        missing.push(`subjects[${i}].profile`);
      if (typeof s.commitment_digest_hex !== "string" || !HEX64_RE.test(s.commitment_digest_hex))
        missing.push(`subjects[${i}].commitment_digest_hex`);
    });
  }

  // §7.3: required members of the signed payload beside the anchor. The anchor
  // commitment is a sibling of `anchor`, never inside it (the closed anchor
  // above already refuses it there).
  if (typeof p.anchor_commitment_digest_hex !== "string" || !HEX64_RE.test(p.anchor_commitment_digest_hex))
    missing.push("payload.anchor_commitment_digest_hex");
  if (typeof p.system_id !== "string" || !ASCII_TOKEN_RE.test(p.system_id)) missing.push("payload.system_id");
  if (typeof p.rules_version !== "string" || !ASCII_TOKEN_RE.test(p.rules_version))
    missing.push("payload.rules_version");
  if ("anchor_canon_digest_hex" in p &&
      (typeof p.anchor_canon_digest_hex !== "string" || !HEX64_RE.test(p.anchor_canon_digest_hex)))
    missing.push("payload.anchor_canon_digest_hex (64 lowercase hex)");
  if ("payload_canon_digest_hex" in raw &&
      (typeof raw.payload_canon_digest_hex !== "string" || !HEX64_RE.test(raw.payload_canon_digest_hex)))
    missing.push("payload_canon_digest_hex (64 lowercase hex)");

  // §7.4: exactly one signature object, the issuer's composite signature.
  const sigs = raw.signatures as unknown[];
  if (sigs.length !== 1) {
    missing.push(`signatures[] must hold exactly one issuer signature, got ${sigs.length} entries`);
  } else {
    validateIssuerSignature(sigs[0], missing);
  }

  if (missing.length > 0) return reject(`CCSP/1 structure invalid: ${missing.join("; ")}`);

  // §7.3: the certificate names its system domain and rules domain; they must
  // be the ones this verifier evaluates under.
  if (p.system_id !== config.system_id) {
    return reject(`payload.system_id "${p.system_id}" is not this system domain ("${config.system_id}")`);
  }
  if (!config.supported_rules_versions.includes(p.rules_version as string)) {
    builder.fail("BASE_CERTIFICATE_STRUCTURE_VALID", "UNSUPPORTED",
      `payload.rules_version "${p.rules_version}" is not a rules version this verifier evaluates`);
    return false;
  }

  // The rules domain fixes the set of subject profiles it admits. A profile
  // outside that set makes the certificate non-conformant: it fails closed here,
  // whether or not this verifier could canonicalize it.
  const notAdmitted = (subjects as { profile: string }[])
    .map((s, i) => ({ i, profile: s.profile }))
    .filter(({ profile }) => !config.admitted_subject_profiles.includes(profile));
  if (notAdmitted.length > 0) {
    return reject(
      "subject profile not admitted by the rules domain: " +
        notAdmitted.map(({ i, profile }) => `subjects[${i}].profile=${profile}`).join("; ")
    );
  }

  // CCCP/1 §8.2: anchor_commitment = SHA3-256(ASCII(nonce_hex) || ASCII(SHA3-256(JCS(anchor)))).
  const anchorCanonHex = digestHexBytes(jcsCanonicalizeBytes(anchor));
  const recomputedCommitment = digestHexText((anchor.nonce_hex as string) + anchorCanonHex);
  if (recomputedCommitment !== p.anchor_commitment_digest_hex) {
    return reject(
      `anchor_commitment_digest_hex mismatch: recomputed="${recomputedCommitment}", ` +
        `declared="${p.anchor_commitment_digest_hex}"`
    );
  }

  // CCCP/1 §7.3: a published digest is recomputed, and a mismatch fails closed.
  if ("anchor_canon_digest_hex" in p && p.anchor_canon_digest_hex !== anchorCanonHex) {
    return reject(
      `payload.anchor_canon_digest_hex mismatch: recomputed="${anchorCanonHex}", ` +
        `declared="${p.anchor_canon_digest_hex}"`
    );
  }
  if ("payload_canon_digest_hex" in raw) {
    const payloadDigest = digestHexBytes(jcsCanonicalizeBytes(p));
    if (raw.payload_canon_digest_hex !== payloadDigest) {
      return reject(
        `payload_canon_digest_hex mismatch: recomputed="${payloadDigest}", ` +
          `declared="${raw.payload_canon_digest_hex}"`
      );
    }
  }

  return true;
}

/**
 * CCSP/1 §7.4: the issuer signature object, its signer and its components are
 * closed, with the layout `composite-signature/1` §8 fixes. Defects are pushed
 * onto `missing`. Whether the declared profile is the rules domain's, and
 * whether the components verify, is decided by `verifyAuthenticity`.
 */
function validateIssuerSignature(sig: unknown, missing: string[]): void {
  if (!isPlainObject(sig)) {
    missing.push("signatures[0] (object)");
    return;
  }
  const extra = extraMembers(sig, [...ISSUER_REQUIRED, ...ISSUER_OPTIONAL]);
  if (extra.length > 0) missing.push(`issuer signature members not allowed: ${extra.join(", ")}`);
  if (sig.role !== "issuer") missing.push('signatures[0].role "issuer"');
  if (typeof sig.alg !== "string" || !ASCII_TOKEN_RE.test(sig.alg)) missing.push("issuer alg");
  if (sig.mode !== "AND") missing.push('issuer composite mode "AND"');
  if (sig.sig_target !== "payload_canon_digest_hex") missing.push('issuer sig_target "payload_canon_digest_hex"');
  if ("kid" in sig && (typeof sig.kid !== "string" || !ASCII_TOKEN_RE.test(sig.kid) || sig.kid.length > 128))
    missing.push("issuer kid (ASCII token, at most 128 characters)");

  const signer = sig.signer;
  if (!isPlainObject(signer)) {
    missing.push("issuer signer (object)");
  } else {
    const signerExtra = extraMembers(signer, SIGNER_MEMBERS);
    if (signerExtra.length > 0) missing.push(`issuer signer members not allowed: ${signerExtra.join(", ")}`);
    if (typeof signer.id !== "string" || !ASCII_TOKEN_RE.test(signer.id) || signer.id.length > 256)
      missing.push("issuer signer.id (ASCII token, at most 256 characters)");
    if (typeof signer.pub_p256_b64 !== "string" || signer.pub_p256_b64.length === 0)
      missing.push("issuer signer.pub_p256_b64");
    if (typeof signer.pub_mldsa_b64 !== "string" || signer.pub_mldsa_b64.length === 0)
      missing.push("issuer signer.pub_mldsa_b64");
  }

  // Components: exactly two, ECDSA P-256 first and ML-DSA-65 second.
  const comps = sig.signatures;
  if (!Array.isArray(comps) || comps.length !== 2) {
    missing.push("issuer composite components (exactly two: ECDSA-P256-SHA3-256, then ML-DSA-65)");
    return;
  }
  COMPONENTS.forEach(({ alg, members }, i) => {
    const c: unknown = comps[i];
    if (!isPlainObject(c) || c.alg !== alg) {
      missing.push(`issuer component ${i} must be ${alg}`);
      return;
    }
    const cExtra = extraMembers(c, members);
    const cMissing = members.filter((k) => !(k in c));
    if (cExtra.length > 0 || cMissing.length > 0)
      missing.push(`issuer component ${i} members must be exactly ${members.join(", ")}`);
    if (typeof c.sig_b64 !== "string" || c.sig_b64.length === 0) missing.push(`issuer component ${i} sig_b64`);
    if (alg === "ECDSA-P256-SHA3-256" && (c.encoding !== "raw-rs-64" || c.low_s !== true))
      missing.push('issuer ECDSA component encoding "raw-rs-64" and low_s true');
  });
}

/**
 * Verify the composite issuer signature (CERTCRYPT Composite Signature Profile, canonical profile): the ECDSA
 * P-256 and ML-DSA-65 components over M' = domain-separated SHA3-256(JCS(payload)). AND.
 */
function verifyAuthenticity(
  cert: BaseCertificate,
  config: SystemDomainConfig,
  builder: ResultBuilder
): boolean {
  const issuerSig = cert.signatures[0];

  // The expected profile is the rules domain's, never the one the signature
  // declares: a signature under another profile fails even if it would verify.
  if (issuerSig.alg !== config.signature_profile) {
    builder.fail("BASE_CERTIFICATE_AUTHENTIC", "ISSUED_INVALID",
      `issuer signature profile "${issuerSig.alg}" is not the rules domain's ` +
        `"${config.signature_profile}"`);
    return false;
  }

  const canonicalPayloadBytes = jcsCanonicalizeBytes(cert.payload);
  const payloadDigest = digestHexBytes(canonicalPayloadBytes);

  // CCSP/1 §7.4: the one canonical encoding of `pub_p256_b64` is SEC1
  // uncompressed (65 bytes, 0x04 prefix). Any other encoding of the same key is
  // malformed for this field, not an equivalent.
  const p256Pub = decodeBase64Strict(issuerSig.signer.pub_p256_b64);
  if (p256Pub === null || p256Pub.length !== 65 || p256Pub[0] !== 0x04) {
    builder.fail("BASE_CERTIFICATE_AUTHENTIC", "REJECTED",
      "composite issuer signature: malformed ECDSA-P256-SHA3-256 material " +
        "(signer.pub_p256_b64 must be a base64 SEC1 uncompressed key of 65 bytes)");
    return false;
  }

  const result = verifyComposite(
    issuerSig.alg,
    payloadDigest,
    { alg: issuerSig.alg, mode: issuerSig.mode, signatures: issuerSig.signatures },
    {
      classicalPubB64: issuerSig.signer.pub_p256_b64,
      mldsaPubB64: issuerSig.signer.pub_mldsa_b64,
    }
  );

  // The PQC plane is NORMATIVE (the ML-DSA-65 component of the composite), not
  // a sidecar: its outcome is carried by BASE_CERTIFICATE_AUTHENTIC below. The
  // pqc result slot only surfaces that same component outcome on its own, on
  // every path — pass, fail or not run — so it never reads "not_attempted" for
  // a component that was in fact verified and failed.
  builder.setPqcResult({
    performed: result.mldsa.performed,
    algorithm: "ML-DSA-65",
    passed: result.mldsa.passed,
    reason: result.mldsa.reason,
  });

  if (!result.valid) {
    // The ML-DSA-65 component could not be run. Distinguish a genuinely absent
    // PQC runtime (cannot assert the post-quantum floor → UNSUPPORTED) from
    // malformed PQC material in the certificate (a structural defect → REJECTED).
    if (result.mldsa.performed === false) {
      const reason = result.mldsa.reason ?? "";
      if (reason.startsWith("unsupported_runtime")) {
        builder.fail("BASE_CERTIFICATE_AUTHENTIC", "UNSUPPORTED",
          `composite issuer signature: ML-DSA-65 runtime unavailable (${reason})`);
      } else {
        builder.fail("BASE_CERTIFICATE_AUTHENTIC", "REJECTED",
          `composite issuer signature: malformed ML-DSA-65 material (${reason})`);
      }
      return false;
    }
    // A malformed classical component (bad base64 / wrong length) is a
    // structural defect → REJECTED; a well-formed-but-failing one → ISSUED_INVALID.
    if (result.classical.passed === false && isMalformedReason(result.classical.reason)) {
      builder.fail("BASE_CERTIFICATE_AUTHENTIC", "REJECTED",
        `composite issuer signature: malformed ${result.classical.alg ?? "classical"} material (${result.classical.reason})`);
      return false;
    }
    const why = !result.mldsa.passed
      ? `ML-DSA-65 component failed (${result.mldsa.reason})`
      : `${result.classical.alg ?? "classical"} component failed (${result.classical.reason})`;
    builder.fail("BASE_CERTIFICATE_AUTHENTIC", "ISSUED_INVALID",
      `composite issuer signature invalid over M'(payload_canon_digest_hex): ${why}`);
    return false;
  }

  builder.pass("BASE_CERTIFICATE_AUTHENTIC");
  return true;
}

/** RFC 4648 base64 (standard alphabet, padded), or null if `v` is not that. */
function decodeBase64Strict(v: string): Uint8Array | null {
  if (v.length === 0 || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(v)) return null;
  const bin = atob(v);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

