/**
 * Side-effect module that installs the Node backend.
 *
 * Imported by `core/verify-node.ts` (and by the tests and the CLI). Keeping the
 * `node:crypto` import behind this module — rather than inside the selector —
 * is what lets a browser bundle exclude it entirely: nothing a browser imports
 * ever reaches this file, so `node:crypto` never enters the module graph.
 */
import { nodeProvider } from "./node.js";
import { registerNodeProvider } from "./index.js";
// The filesystem bridge travels with the Node backend: anything running under
// Node (CLI, tests, conformance harness) can read artifacts by path.
import "../../input/register-node-fs.js";

registerNodeProvider(nodeProvider);

export { nodeProvider };
