// RFC 4514 (LDAP: String Representation of Distinguished Names) parser.
// This is the routing-boundary DN recognizer: a real recursive-descent parser over the grammar,
// not a shape heuristic. It is deliberately conservative: anything it cannot fully parse is
// reported as "not a DN" (undefined) rather than guessed at.
export type AttributeTypeAndValue = Readonly<{ type: string; value: string; hex: boolean }>;
export type Rdn = Readonly<{ attributes: readonly AttributeTypeAndValue[] }>;
export type DistinguishedName = Readonly<{ rdns: readonly Rdn[] }>;

const ATTRIBUTE_TYPE = /^(?:[A-Za-z][A-Za-z0-9-]*|(?:0|[1-9]\d*)(?:\.(?:0|[1-9]\d*))+)/;
const ESCAPABLE = new Set([" ", "\"", "#", "+", ",", ";", "<", "=", ">", "\\"]);
const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });

class Cursor {
  index = 0;
  constructor(readonly text: string) {}
  get done(): boolean { return this.index >= this.text.length; }
  peek(): string | undefined { return this.text[this.index]; }
}

function parseHexPair(cursor: Cursor): number | undefined {
  const pair = cursor.text.slice(cursor.index, cursor.index + 2);
  if (!/^[0-9a-fA-F]{2}$/.test(pair)) return undefined;
  cursor.index += 2;
  return Number.parseInt(pair, 16);
}

// Attribute value string form: a run of literal characters and backslash escapes, ended by an
// unescaped ',', '+', or end of input. Escaped bytes accumulate and are flushed through UTF-8
// decoding, so a multi-byte character split across \xx\xx pairs decodes correctly. A raw leading
// '#' or space, or a raw trailing space, is invalid: RFC 4514 requires those to be escaped.
function parseValue(cursor: Cursor): string | undefined {
  let out = "";
  let pending: number[] = [];
  let sawAnyChar = false;
  let lastWasRawSpace = false;
  const flush = (): boolean => {
    if (!pending.length) return true;
    try { out += UTF8_DECODER.decode(Uint8Array.from(pending)); pending = []; return true; }
    catch { return false; }
  };
  while (!cursor.done) {
    const ch = cursor.peek() as string;
    if (ch === "," || ch === "+") break;
    if (ch === "\\") {
      cursor.index++;
      const byte = parseHexPair(cursor);
      if (byte !== undefined) { pending.push(byte); sawAnyChar = true; lastWasRawSpace = false; continue; }
      const escaped = cursor.peek();
      if (escaped === undefined || !ESCAPABLE.has(escaped)) return undefined;
      if (!flush()) return undefined;
      out += escaped; cursor.index++; sawAnyChar = true; lastWasRawSpace = false; continue;
    }
    if (ch === "\"" || ch === "<" || ch === ">" || ch === ";" || ch === "=" || ch === "\0") return undefined;
    if (ch === "#" && !sawAnyChar) return undefined;
    if (ch === " " && !sawAnyChar) return undefined;
    if (!flush()) return undefined;
    out += ch; cursor.index++; sawAnyChar = true; lastWasRawSpace = ch === " ";
  }
  if (lastWasRawSpace) return undefined;
  if (!flush()) return undefined;
  return out;
}

// Attribute value hex form: '#' followed by an even-length run of hex pairs, representing a
// BER-encoded value. Stored as the raw hex text; ldap-axi does not need to decode the BER content
// to route on it.
function parseHexValue(cursor: Cursor): string | undefined {
  const start = cursor.index;
  while (!cursor.done && /[0-9a-fA-F]/.test(cursor.peek() as string)) cursor.index++;
  const hex = cursor.text.slice(start, cursor.index);
  if (hex.length === 0 || hex.length % 2 !== 0) return undefined;
  return hex;
}

function parseAttributeTypeAndValue(cursor: Cursor): AttributeTypeAndValue | undefined {
  const match = ATTRIBUTE_TYPE.exec(cursor.text.slice(cursor.index));
  if (!match) return undefined;
  const type = match[0];
  cursor.index += type.length;
  if (cursor.peek() !== "=") return undefined;
  cursor.index++;
  if (cursor.peek() === "#") {
    cursor.index++;
    const hex = parseHexValue(cursor);
    return hex === undefined ? undefined : { type, value: hex, hex: true };
  }
  const value = parseValue(cursor);
  return value === undefined ? undefined : { type, value, hex: false };
}

function parseRdn(cursor: Cursor): Rdn | undefined {
  const attributes: AttributeTypeAndValue[] = [];
  for (;;) {
    const atv = parseAttributeTypeAndValue(cursor);
    if (!atv) return undefined;
    attributes.push(atv);
    if (cursor.peek() === "+") { cursor.index++; continue; }
    break;
  }
  return { attributes };
}

/** Parses an RFC 4514 distinguished name string. Returns undefined for anything not fully valid. */
export function parseDn(text: string): DistinguishedName | undefined {
  if (text === "") return { rdns: [] };
  const cursor = new Cursor(text);
  const rdns: Rdn[] = [];
  for (;;) {
    const rdn = parseRdn(cursor);
    if (!rdn) return undefined;
    rdns.push(rdn);
    if (cursor.done) break;
    if (cursor.peek() === ",") { cursor.index++; continue; }
    return undefined;
  }
  return { rdns };
}

/** True only for a syntactically valid, non-empty distinguished name. */
export function isDn(text: string): boolean {
  const dn = parseDn(text);
  return dn !== undefined && dn.rdns.length > 0;
}
