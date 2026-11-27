/**
 * Strict JSON parsing: RFC 8259 grammar, and no object may carry the same member
 * name twice, at any depth.
 *
 * `JSON.parse` accepts duplicate member names and keeps the last value. Another
 * parser may keep the first, or reject, so two verifiers reading the same bytes
 * could evaluate different data. A duplicate therefore makes the input
 * non-conformant (CCSP/1 §8.1, and the JSON subject profiles), and this parser
 * fails closed on it.
 *
 * Member names are compared after decoding their escapes, so `"anchor"` and
 * `"\u0061nchor"` are the same name. Only object members are compared: repeated
 * elements of an array are ordinary data, and the same name in two different
 * objects is not a duplicate.
 *
 * The scan validates the whole document before `JSON.parse` builds the value, so
 * the value returned is exactly the one `JSON.parse` would produce for a
 * document without duplicates.
 */

/** Thrown for a document that is not valid JSON or that repeats a member name. */
export class StrictJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictJsonError";
  }
}

/** Parse `text` as strict JSON (see the module comment). Throws `StrictJsonError`. */
export function strictJsonParse(text: string): unknown {
  scanStrict(text);
  return JSON.parse(text);
}

/** Maximum nesting depth accepted; deeper input is refused, not truncated. */
const MAX_DEPTH = 512;

interface ObjectFrame {
  kind: "object";
  names: Set<string>;
}
interface ArrayFrame {
  kind: "array";
}
type Frame = ObjectFrame | ArrayFrame;

function scanStrict(text: string): void {
  let i = 0;
  const n = text.length;
  const stack: Frame[] = [];

  const fail = (what: string): never => {
    throw new StrictJsonError(`invalid JSON at offset ${i}: ${what}`);
  };

  const skipWs = (): void => {
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) i++;
      else break;
    }
  };

  // Returns the raw token of a string starting at text[i] === '"'.
  const readString = (): string => {
    const start = i;
    i++; // opening quote
    while (i < n) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        return text.slice(start, i);
      }
      if (c === 0x5c) {
        const e = text[i + 1];
        if (e === "u") {
          if (!/^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) fail("bad \\u escape");
          i += 6;
        } else if (e !== undefined && '"\\/bfnrt'.includes(e)) {
          i += 2;
        } else {
          fail("bad escape");
        }
        continue;
      }
      if (c < 0x20) fail("control character in string");
      i++;
    }
    return fail("unterminated string");
  };

  const readNumber = (): void => {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(text.slice(i, i + 4096));
    if (!m || m[0].length === 0) fail("bad number");
    i += m![0].length;
  };

  const readLiteral = (): void => {
    for (const lit of ["true", "false", "null"]) {
      if (text.startsWith(lit, i)) {
        i += lit.length;
        return;
      }
    }
    fail("unexpected token");
  };

  // Reads one value. Scalars are consumed; a container pushes a frame and
  // returns, and its members are consumed by the main loop.
  const readValue = (): void => {
    skipWs();
    if (i >= n) fail("unexpected end of input");
    const ch = text[i];
    if (ch === "{" || ch === "[") {
      if (stack.length >= MAX_DEPTH) fail(`nesting deeper than ${MAX_DEPTH}`);
      i++;
      stack.push(ch === "{" ? { kind: "object", names: new Set() } : { kind: "array" });
      skipWs();
      if (text[i] === (ch === "{" ? "}" : "]")) {
        i++;
        stack.pop();
        return;
      }
      if (ch === "{") readMemberName(stack[stack.length - 1] as ObjectFrame);
      else readValue();
      return;
    }
    if (ch === '"') readString();
    else if (ch === "-" || (ch >= "0" && ch <= "9")) readNumber();
    else readLiteral();
  };

  // Reads `"name" :` and the value that follows.
  const readMemberName = (frame: ObjectFrame): void => {
    skipWs();
    if (text[i] !== '"') fail("expected member name");
    const raw = readString();
    const name = JSON.parse(raw) as string;
    if (frame.names.has(name)) {
      throw new StrictJsonError(`duplicate member name ${JSON.stringify(name)}`);
    }
    frame.names.add(name);
    skipWs();
    if (text[i] !== ":") fail("expected ':'");
    i++;
    readValue();
  };

  readValue();
  // After each completed value, close or continue the enclosing containers.
  while (stack.length > 0) {
    skipWs();
    const frame = stack[stack.length - 1];
    const close = frame.kind === "object" ? "}" : "]";
    if (text[i] === close) {
      i++;
      stack.pop();
      continue;
    }
    if (text[i] !== ",") fail(`expected ',' or '${close}'`);
    i++;
    if (frame.kind === "object") readMemberName(frame);
    else readValue();
  }
  skipWs();
  if (i !== n) fail("trailing content");
}
