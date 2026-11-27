#!/usr/bin/env node
// Runs every compiled test under dist/ with the Node.js test runner.
//
// The test files are listed here and passed to `node --test` by name, so the
// suite runs the same on every supported Node.js version: the runner of
// Node.js 20 does not expand a pattern such as "dist/**/*.test.js".
//
// Arguments are passed to Node.js before --test (for example --import <hook>).
import {spawnSync} from 'node:child_process';
import {readdirSync} from 'node:fs';
import {join} from 'node:path';

function testFiles(dir) {
  return readdirSync(dir, {withFileTypes: true}).flatMap((entry) => {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) return testFiles(path);
    return entry.name.endsWith('.test.js') ? [path] : [];
  });
}

const files = testFiles('dist').sort();
if (files.length === 0) {
  console.error('run-tests: no test files under dist/; build first (npm run build)');
  process.exit(1);
}
const run = spawnSync(process.execPath, [...process.argv.slice(2), '--test', ...files], {stdio: 'inherit'});
process.exit(run.status ?? 1);
