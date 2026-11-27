/**
 * Strict base64: one byte string, one accepted spelling.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { strictBase64Decode } from "./bytes.js";

test("strictBase64Decode accepts canonical base64 and rejects non-canonical trailing bits", () => {
  assert.deepEqual([...strictBase64Decode("AA==", "x")], [0]);
  assert.deepEqual([...strictBase64Decode("AAA=", "x")], [0, 0]);
  assert.deepEqual([...strictBase64Decode("AAAA", "x")], [0, 0, 0]);
  // Same bytes, nonzero unused bits: refused.
  assert.throws(() => strictBase64Decode("AB==", "x"), /non-canonical/);
  assert.throws(() => strictBase64Decode("AAB=", "x"), /non-canonical/);
  // Unpadded and misplaced padding stay refused.
  assert.throws(() => strictBase64Decode("AA", "x"));
  assert.throws(() => strictBase64Decode("A=AA", "x"));
});
