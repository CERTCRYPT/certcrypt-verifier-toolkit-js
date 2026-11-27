/**
 * Load a verifier-local subject-material map from disk (verifier-toolkit/1).
 *
 * verifier-toolkit/1 §8.5.1 fixes the *logical* mapping (zero-based subject index → bytes) and is
 * explicit that "the certificate is the sole source of cardinality and order".
 * The container is an implementation choice; this loader defines one container
 * for the JS toolkit: a JSON manifest that lists subjects in index order, each
 * pointing at the byte files that carry its material. File paths are resolved
 * relative to the manifest's own directory.
 *
 * The manifest does NOT declare the subject `profile`: the profile (subject.binary/1,
 * subject.collection/1, subject.text/1, subject.email/1, …) is read from the
 * certificate's `anchor.subjects[i].profile`, never from the material delivery.
 * A delivery may therefore never contradict the certificate about what a subject
 * is — it only supplies that subject's bytes. The manifest entry shape signals
 * only how the bytes are packaged:
 *
 *   - a single blob (the common case — binary/text/email and any other
 *     single-material profile): `{ "material_file": "subject-0.bin" }`
 *   - a collection's ordered leaves: `{ "leaf_files": ["leaf-0.bin", "leaf-1.bin"] }`.
 *     The descriptor is read from the signed subject (`subjects[i].collection`). An
 *     optional `collection` member may accompany the leaves; when present it must
 *     match the signed descriptor canonically.
 *   - an AI-decision record together with any disclosed parts:
 *     `{ "material_file": "record.json", "materials": [
 *       { "id": "prompt", "material_file": "prompt.txt" }
 *     ] }`. Each part id comes from the matched record. A binary part may carry
 *     `{ "id", "prehashed": true, "subject_local_digest_hex" }` instead.
 *
 *   [
 *     { "material_file": "subject-0.bin" },
 *     { "leaf_files": ["leaf-0.bin", "leaf-1.bin", "leaf-2.bin"] }
 *   ]
 *
 * The array index IS the subject index. Bytes are read byte-exact: this loader
 * never normalizes, re-encodes, or strips anything. It does not validate
 * the material against the certificate — that is verifyOriginalMaterial's job
 * (it applies the certificate's declared profile, recomputes the commitment, and
 * fails closed UNSUPPORTED for a profile the toolkit does not implement). The
 * loader only resolves the container into the in-memory SubjectMaterialMap.
 */
import { getFileSystemBridge } from "./fs-bridge.js";
import { strictJsonParse } from "./strict-json.js";
import type {
  AiDecisionMaterial,
  CollectionMaterial,
  SubjectMaterialMap,
} from "../types/index.js";

interface BlobEntry {
  material_file: string;
  /** subject.ai-decision/1 only: disclosed parts keyed by their record id. */
  materials?: NestedMaterialEntry[];
}
interface NestedMaterialEntry {
  id: string;
  material_file?: string;
  prehashed?: true;
  subject_local_digest_hex?: string;
  byte_length?: number;
}
interface CollectionEntry {
  /** Optional: the authoritative descriptor is the one signed in the subject. */
  collection?: unknown;
  leaf_files: string[];
}
type ManifestEntry = BlobEntry | CollectionEntry;

function resolveRelative(baseDir: string, p: string): string {
  return getFileSystemBridge().resolvePath(baseDir, p);
}

/**
 * Read the subject-material manifest at `manifestPath` and build the
 * SubjectMaterialMap keyed by zero-based subject index.
 *
 * Throws on a manifest that is not a JSON array or whose entries are malformed;
 * the CLI surfaces that as a usage error. Per-subject *verification* outcomes
 * (missing subject, cardinality mismatch, unsupported profile, commitment
 * mismatch) are decided later by verifyOriginalMaterial against the certificate.
 */
export function loadOriginalMaterial(manifestPath: string): SubjectMaterialMap {
  const fs = getFileSystemBridge();
  const baseDir = fs.directoryOf(manifestPath);
  const raw = fs.readTextFile(manifestPath);
  const parsed: unknown = strictJsonParse(raw);
  if (!Array.isArray(parsed)) {
    throw new Error(
      `original-material manifest must be a JSON array (index → subject material), got ${typeof parsed}`,
    );
  }

  const map: SubjectMaterialMap = new Map();
  parsed.forEach((entry: ManifestEntry, index: number) => {
    // A collection delivery carries its ordered leaves; anything else is a
    // single blob. We distinguish by the SHAPE of the delivery, not by a
    // declared type — the certificate alone decides the profile.
    if (entry && "leaf_files" in entry) {
      const c = entry as CollectionEntry;
      if (!Array.isArray(c.leaf_files)) {
        throw new Error(
          `original-material manifest entry ${index} has "leaf_files" but it is not an array`,
        );
      }
      const leaves: Uint8Array[] = c.leaf_files.map((f) =>
        fs.readBinaryFile(resolveRelative(baseDir, f)),
      );
      // Only carry `collection` when the delivery actually declared one; an
      // explicit `undefined` would read as "delivered but empty" downstream.
      const material: CollectionMaterial =
        c.collection !== undefined ? { collection: c.collection, leaves } : { leaves };
      map.set(index, material);
    } else if (entry && "material_file" in entry) {
      const b = entry as BlobEntry;
      if (typeof b.material_file !== "string") {
        throw new Error(
          `original-material manifest entry ${index}: "material_file" must be a path string`,
        );
      }
      const record = fs.readBinaryFile(resolveRelative(baseDir, b.material_file));
      if (b.materials === undefined) {
        map.set(index, record);
        return;
      }
      if (!Array.isArray(b.materials)) {
        throw new Error(`original-material manifest entry ${index}: "materials" must be an array`);
      }
      const nested = new Map<string, Uint8Array | { prehashed: true; subject_local_digest_hex: string; byte_length?: number }>();
      for (const part of b.materials) {
        if (!part || typeof part.id !== "string") {
          throw new Error(`original-material manifest entry ${index}: every nested material needs a string "id"`);
        }
        if (nested.has(part.id)) {
          throw new Error(`original-material manifest entry ${index}: duplicate nested material id ${JSON.stringify(part.id)}`);
        }
        if (part.prehashed === true) {
          if (part.material_file !== undefined || typeof part.subject_local_digest_hex !== "string") {
            throw new Error(`original-material manifest entry ${index}: prehashed part ${JSON.stringify(part.id)} must carry only its digest`);
          }
          nested.set(part.id, {
            prehashed: true,
            subject_local_digest_hex: part.subject_local_digest_hex,
            ...(part.byte_length === undefined ? {} : { byte_length: part.byte_length }),
          });
          continue;
        }
        if (typeof part.material_file !== "string") {
          throw new Error(
            `original-material manifest entry ${index}: nested material ${JSON.stringify(part.id)} needs "material_file"`,
          );
        }
        nested.set(part.id, fs.readBinaryFile(resolveRelative(baseDir, part.material_file)));
      }
      const material: AiDecisionMaterial = { record, materials: nested };
      map.set(index, material);
    } else {
      throw new Error(
        `original-material manifest entry ${index} must carry either "material_file" (a single blob) or "leaf_files" (a collection)`,
      );
    }
  });

  return map;
}
