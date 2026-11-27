/**
 * File-reading bridge.
 *
 * `VerifierRequest` accepts artifacts either in memory or by path. Paths are a
 * Node convenience (the CLI reads files); a browser always supplies artifacts in
 * memory, because the material it verifies is already in the page.
 *
 * Keeping `node:fs`/`node:path` behind this bridge is what lets a browser bundle
 * exclude them: nothing a browser imports reaches the Node implementation, so
 * the built-ins never enter the module graph. If a path IS supplied without a
 * bridge registered, the read fails with a clear error rather than a bundler's
 * cryptic "module not found".
 */

export interface FileSystemBridge {
  readTextFile(path: string): string;
  readBinaryFile(path: string): Uint8Array;
  /** Resolve `p` against `baseDir` unless it is already absolute. */
  resolvePath(baseDir: string, p: string): string;
  /** The directory portion of a path. */
  directoryOf(path: string): string;
}

let _bridge: FileSystemBridge | null = null;

/** Install the Node implementation. Called by `register-node-fs.ts`. */
export function registerFileSystemBridge(bridge: FileSystemBridge): void {
  _bridge = bridge;
}

export function hasFileSystemBridge(): boolean {
  return _bridge !== null;
}

/**
 * The active bridge. Throws when a path-based artifact is requested in a runtime
 * that has no filesystem — which is a caller error (supply the artifact in
 * memory), and is reported as one.
 */
export function getFileSystemBridge(): FileSystemBridge {
  if (!_bridge) {
    throw new Error(
      "no filesystem available in this runtime: supply artifacts in memory " +
        "(base_certificate, independence_proof, original_material, …) rather " +
        "than by *_path"
    );
  }
  return _bridge;
}
