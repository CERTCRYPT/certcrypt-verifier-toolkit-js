/**
 * Browser entry point — `verify()` with the @noble backend.
 *
 * Import this from a browser bundle. Nothing reachable from here imports
 * `node:crypto` or `node:fs`, so no aliasing, polyfilling or `externals` config
 * is needed: the module graph simply never contains a Node built-in.
 *
 * Artifacts must be supplied IN MEMORY (`base_certificate`, `independence_proof`,
 * `original_material`, …) rather than by path — `VerifierRequest` accepts both
 * forms, and the in-memory value wins. The `*_path` fields are Node-only and
 * unreachable here.
 *
 * Why a browser build exists at all: computing an artifact's commitment requires
 * the ORIGINAL MATERIAL. Uploading that to a server would transmit exactly the
 * private content the protocol is designed never to require — so the verifier
 * runs where the material already is, and the material never leaves the machine.
 */
import { setCryptoProvider, webProvider } from "./crypto/provider/index.js";

// Explicit rather than implicit: a bundler that somehow did include the Node
// entry would otherwise leave the Node backend registered and win the default.
setCryptoProvider(webProvider);

// The same public surface as the Node entry — code written against one runs on
// the other unchanged.
export * from "./public-api.js";
