/**
 * Node entry point — `verify()` with the `node:crypto` backend installed.
 *
 * This is the entry the CLI, the unit tests and the conformance harness use. The
 * import below is for side effect: it registers the Node backend before any
 * verification runs.
 *
 * Browsers import `@certcrypt/verifier-toolkit/web` (the package root resolves
 * to it under the `browser` condition) and never pull `node:crypto` into the
 * bundle.
 */
import "./crypto/provider/register-node.js";
import "./input/register-node-fs.js";

// The same public surface as the browser entry — code written against one runs
// on the other unchanged.
export * from "./public-api.js";
