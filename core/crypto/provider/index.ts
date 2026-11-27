/**
 * Crypto provider selection.
 *
 * The verification core calls `getCryptoProvider()` and never imports a backend
 * directly, so the same core runs on Node and in a browser with no conditional
 * code inside the verification logic itself.
 *
 * Selection rule:
 *   1. an explicit `setCryptoProvider(...)` always wins (tests pin a backend
 *      this way, and an embedder can force one);
 *   2. otherwise the Node backend, if `register-node.ts` has installed it;
 *   3. otherwise the Web backend.
 *
 * Why the Node backend is the default under Node: it is the path the CLI, the
 * unit tests and the conformance harness run on. And the
 * selection needs no runtime environment sniffing — no `typeof window`, no
 * `process.versions` probe, both of which misreport under SSR and bundler shims.
 * Registration is a build-time fact: a browser bundle never imports the Node
 * entry point, so no backend is registered and the Web one is used.
 */
import type { CryptoProvider } from "./types.js";
import { webProvider } from "./web.js";

export type { CryptoProvider } from "./types.js";
export { webProvider } from "./web.js";

let _override: CryptoProvider | null = null;
let _resolved: CryptoProvider | null = null;
let _nodeBackend: CryptoProvider | null = null;

/**
 * Register the Node backend. Called by `core/crypto/provider/register-node.ts`,
 * which the Node entry point imports for side effect.
 *
 * The registration is inverted deliberately: if this module imported `./node.js`
 * itself, every browser bundle would pull `node:crypto` into the graph and a
 * bundler would either fail to resolve it or shim it. By having Node hand its
 * backend in, a browser build simply never registers one and resolves to the Web
 * backend — no aliasing, no `externals` config, no polyfill required.
 */
export function registerNodeProvider(provider: CryptoProvider): void {
  _nodeBackend = provider;
  _resolved = null;
}

/**
 * `CERTCRYPT_CRYPTO_BACKEND=web` forces the Web backend even under Node.
 *
 * This exists so the SAME unit and conformance suites can be run against the
 * browser primitives (`npm run test:web`, `npm run test:conformance:web`) — the
 * browser path is audited by the real vectors, not by a separate set of tests
 * that could drift from them. It is a test affordance: a browser never reads it
 * (no `process`), and it can only select between two verification backends,
 * neither of which can weaken a verdict.
 */
function envForcesWeb(): boolean {
  try {
    return (
      typeof process !== "undefined" &&
      process.env?.CERTCRYPT_CRYPTO_BACKEND === "web"
    );
  } catch {
    return false;
  }
}

/**
 * Force a backend. Called by the equivalence tests and the conformance harness
 * to run the SAME vectors through each provider; an embedder may also use it to
 * pin a backend explicitly.
 */
export function setCryptoProvider(provider: CryptoProvider | null): void {
  _override = provider;
  _resolved = null;
}

/**
 * The active provider. Resolution is cached after the first call; either
 * `setCryptoProvider` or `registerNodeProvider` clears the cache.
 */
export function getCryptoProvider(): CryptoProvider {
  if (_override) return _override;
  if (_resolved) return _resolved;
  _resolved = envForcesWeb() ? webProvider : (_nodeBackend ?? webProvider);
  return _resolved;
}
