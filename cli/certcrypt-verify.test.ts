/**
 * Exit codes of the `certcrypt-verify` CLI outside a verdict: an explicit
 * request for help succeeds, a usage error does not.
 */

import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("./certcrypt-verify.js", import.meta.url));

function run(...args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: "utf8" });
}

for (const flag of ["--help", "-h"]) {
  test(`${flag} prints the usage to stdout and exits 0`, () => {
    const r = run(flag);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /^Usage:/);
    assert.match(r.stdout, /--help/);
    assert.equal(r.stderr, "");
  });
}

test("--help wins over other arguments", () => {
  const r = run("--certificate", "missing.json", "--help");
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^Usage:/);
});

test("no arguments is a usage error: usage on stderr, exit 2", () => {
  const r = run();
  assert.equal(r.status, 2);
  assert.equal(r.stdout, "");
  assert.match(r.stderr, /Usage:/);
});

test("a missing --certificate is a usage error: exit 2", () => {
  const r = run("--target", "issued");
  assert.equal(r.status, 2);
  assert.match(r.stderr, /--certificate, --package or --request is required/);
});
