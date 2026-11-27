/**
 * Side-effect module that installs the Node filesystem bridge.
 *
 * Imported by the Node entry point (and the CLI and tests). A browser never
 * imports this file, so `node:fs` and `node:path` stay out of browser bundles.
 */
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { registerFileSystemBridge } from "./fs-bridge.js";

registerFileSystemBridge({
  readTextFile(path: string): string {
    return readFileSync(path, "utf-8");
  },
  readBinaryFile(path: string): Uint8Array {
    return new Uint8Array(readFileSync(path));
  },
  resolvePath(baseDir: string, p: string): string {
    return isAbsolute(p) ? p : join(baseDir, p);
  },
  directoryOf(path: string): string {
    return dirname(path);
  },
});
