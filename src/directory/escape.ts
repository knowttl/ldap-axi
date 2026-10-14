// RFC 4515 filter-value and RFC 4514 DN-value escaping. This is the one source of truth for
// interpolating caller-supplied text into a filter or a DN: every convenience flag across entry,
// user, and group goes through these functions, never through ldapts's escapeFilter tagged
// template (see docs/design/v1.md §8.1-8.2).
export function filterValue(value: string): string {
  return value.replace(/[\\*()\0]/g, character => ({ "\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29", "\0": "\\00" })[character] ?? character);
}
/** A convenience flag's own contract decides it accepts a wildcard; the '*' itself is never escaped. */
export function wildcardValue(value: string): string { return value.split("*").map(filterValue).join("*"); }
/** Escapes an arbitrary binary value for exact equality matching in a filter (RFC 4515 §3). */
export function binaryFilterValue(buffer: Buffer): string {
  return [...buffer].map(byte => `\\${byte.toString(16).padStart(2, "0")}`).join("");
}
export function dnValue(value: string): string {
  return [...value].map((character, index) => {
    const mustEscape = /[,+=<>;\\"]/.test(character) || (index === 0 && (character === " " || character === "#")) || (index === value.length - 1 && character === " ");
    return mustEscape ? `\\${Buffer.from(character, "utf8").toString("hex")}` : character;
  }).join("");
}
