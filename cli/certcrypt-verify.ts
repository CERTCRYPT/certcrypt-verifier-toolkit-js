#!/usr/bin/env node
/**
 * CERTCRYPT Verifier Toolkit CLI
 *
 * Thin wrapper around core/verify.ts.
 * Output: JSON VerifierResult to stdout.
 * Exit: 0 for *_VALID, 1 for any other verdict, 2 for a usage error;
 * --help / -h prints the usage to stdout and exits 0.
 */
import { readFileSync } from "node:fs";
// Side effect: installs the node:crypto backend and the filesystem bridge. The
// CLI is Node-only, so it always verifies on the audited Node primitives.
import "../core/crypto/provider/register-node.js";
import { verify } from "../core/verify.js";
import { getCertcryptConfig } from "../core/config/default.js";
import { initMlDsa65 } from "../core/crypto/ml-dsa.js";
import { strictJsonParse } from "../core/input/strict-json.js";
import type { VerifierRequest, SystemDomainConfig } from "../core/types/index.js";

const USAGE = `Usage:
  certcrypt-verify --request <path>
  certcrypt-verify --certificate <path> [--proof <path>] [--settlement-material <path>]
                   [--capacity-evidence <path>] [--commitment-inclusion-proof <path>]
                   [--foundation <path>] [--original-material <path>] [--target auto|issued|independent]
  certcrypt-verify --package <path> [--foundation <path>] [--original-material <path>] [--target auto|issued|independent]
  Either form also accepts: [--test-config <path> [--test-root-fingerprint <hex>]]

Options:
  --request <path>              Path to a VerifierRequest JSON file
  --certificate <path>          Path to base certificate JSON
  --proof <path>                Path to independence proof JSON
  --settlement-material <path>  Path to settlement material JSON
  --capacity-evidence <path>    Path to the zero-data capacity evidence JSON
  --commitment-inclusion-proof <path>
                                Path to the per-commitment inclusion proof JSON
  --package <path>              Path to a verification_package JSON (verification-package/1);
                                it carries the certificate and the Independent artifacts, so
                                it is not combined with the per-artifact flags above
  --foundation <path>           Path to system-foundation/1 statement JSON
  --original-material <path>    Path to a subject-material manifest (verifier-toolkit/1);
                                enables complete verification against original material
  --target <target>             Verification target (auto, issued, independent)
  --test-config <path>          TEST-ONLY: verify under a SystemDomainConfig JSON file
                                instead of the published production profile, for a test
                                or self-hosted deployment that supplies its own config.
                                Every signature is still verified; any profile other
                                than the published one yields production_verification: false.
  --test-root-fingerprint <hex> TEST-ONLY: override system_root_fingerprint in the
                                --test-config profile (requires --test-config).
  -h, --help                    Show this help and exit 0
`;

// A usage error: the usage goes to stderr and the exit code is 2.
function usage(): never {
  console.error(USAGE);
  process.exit(2);
}

// An explicit request for help: the usage goes to stdout and the exit code is 0.
function help(): never {
  process.stdout.write(USAGE);
  process.exit(0);
}

const args = process.argv.slice(2);

function getArg(flag: string): string | undefined {
  const idx = args.indexOf(flag);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  return undefined;
}

function hasFlag(flag: string): boolean {
  return args.includes(flag);
}

if (args.includes("--help") || args.includes("-h")) help();
if (args.length === 0) usage();

let request: VerifierRequest;

const requestPath = getArg("--request");
const packagePath = getArg("--package");
const foundationPath = getArg("--foundation");
const originalMaterialPath = getArg("--original-material");
const target = (getArg("--target") ?? "auto") as "auto" | "issued" | "independent";
const optional = {
  ...(foundationPath ? { system_foundation_path: foundationPath } : {}),
  ...(originalMaterialPath ? { original_material_path: originalMaterialPath } : {}),
};
const certPath = getArg("--certificate");
const perArtifact = {
  ...(certPath ? { base_certificate_path: certPath } : {}),
  ...(getArg("--proof") ? { independence_proof_path: getArg("--proof") } : {}),
  ...(getArg("--settlement-material")
    ? { settlement_material_path: getArg("--settlement-material") }
    : {}),
  ...(getArg("--capacity-evidence")
    ? { capacity_evidence_path: getArg("--capacity-evidence") }
    : {}),
  ...(getArg("--commitment-inclusion-proof")
    ? { commitment_inclusion_proof_path: getArg("--commitment-inclusion-proof") }
    : {}),
};
if (requestPath) {
  request = strictJsonParse(readFileSync(requestPath, "utf-8")) as VerifierRequest;
} else if (packagePath) {
  // A per-artifact flag beside --package reaches verify() too, which refuses
  // the combination rather than choosing between two copies of one artifact.
  request = {
    verification_target_requested: target,
    input_mode: "package",
    verification_package_path: packagePath,
    ...perArtifact,
    ...optional,
  };
} else {
  if (!certPath) {
    console.error("Error: --certificate, --package or --request is required");
    usage();
  }
  request = {
    verification_target_requested: target,
    input_mode: "artifact_set",
    ...perArtifact,
    ...optional,
  };
}

// TEST-ONLY config override, supplied as a FILE rather than compiled in.
//
// A test or self-hosted deployment supplies its own config with
// `--test-config <path>`, a JSON SystemDomainConfig. Its addresses and
// identifiers therefore stay with whoever operates that deployment, not in a
// published package: shipping deployment identifiers inside a verifier package
// would publish them as something to build against.
//
// `--test-root-fingerprint` layers a root onto that config. Signatures are
// verified under the override exactly as under the production profile: no
// configuration accepts a signature without verifying it.
//
// Production verification (no flags) uses getCertcryptConfig() unchanged. And the
// override cannot be laundered into a production verdict: verify() compares the
// ENTIRE config against the published profile, so even setting
// --test-root-fingerprint to the published root still yields
// production_verification: false when anything else differs.
const testRootFp = getArg("--test-root-fingerprint");
const testConfigPath = getArg("--test-config");
let baseTestConfig: SystemDomainConfig | undefined;
if (testConfigPath) {
  try {
    baseTestConfig = JSON.parse(
      readFileSync(testConfigPath, "utf8")
    ) as SystemDomainConfig;
  } catch (e) {
    console.error(
      `--test-config: cannot read ${testConfigPath}: ${(e as Error).message}`
    );
    process.exit(2);
  }
}
if (testRootFp && !baseTestConfig) {
  console.error(
    "--test-root-fingerprint requires --test-config <path>: the profile it layers " +
      "onto is supplied by the caller, not built into this package."
  );
  process.exit(2);
}
const configOverride: SystemDomainConfig | undefined = baseTestConfig
  ? {
      ...baseTestConfig,
      ...(testRootFp ? { system_root_fingerprint: testRootFp } : {}),
    }
  : undefined;

// Await the optional ML-DSA-65 backend BEFORE verifying. verify() is synchronous
// and reads the backend synchronously (getMlDsa65); without this await the eager
// init in core/verify.ts races the call and loses, so composite/PQC signatures
// report "unsupported_runtime". The conformance runner already awaits init; the
// CLI must too, or any composite-signed artifact verifies as UNSUPPORTED.
(async () => {
  await initMlDsa65();
  const result = verify(request, configOverride);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  process.exit(result.result_code.endsWith("_VALID") ? 0 : 1);
})();
