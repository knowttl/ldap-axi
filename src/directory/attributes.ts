import { CliError, first, type Entry } from "../core.js";

/** Only caller-owned attribute names may reach this boundary; decoder prose is never exposed. */
export function decodeAttribute<T>(attribute: string, decode: () => T): T {
  try { return decode(); }
  catch { throw new CliError("PROTOCOL_ERROR", `the directory returned a malformed ${attribute} attribute`, ["Check the attribute syntax and directory schema compatibility"]); }
}

export function decodeEntryAttribute<T>(entry: Entry, attributes: string | readonly string[], decode: (value: string) => T): T | undefined {
  for (const attribute of typeof attributes === "string" ? [attributes] : attributes) {
    const raw = first(entry, attribute);
    if (raw !== undefined) return decodeAttribute(attribute, () => decode(raw));
  }
  return undefined;
}
