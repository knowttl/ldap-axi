// Windows SID binary <-> canonical SDDL string ("S-1-5-21-...") conversion.
// Structure (MS-DTYP 2.4.2): 1 byte revision, 1 byte sub-authority count, 6 bytes big-endian
// identifier authority, then that many 4-byte little-endian sub-authorities.
export function decodeSid(buffer: Buffer): string {
  if (buffer.length < 8) throw new Error("SID value is shorter than the fixed 8-byte header");
  const revision = buffer[0];
  const subAuthorityCount = buffer[1];
  if (buffer.length !== 8 + subAuthorityCount * 4) throw new Error("SID value length does not match its declared sub-authority count");
  let identifierAuthority = 0n;
  for (let index = 2; index < 8; index++) identifierAuthority = (identifierAuthority << 8n) | BigInt(buffer[index]);
  const subAuthorities: string[] = [];
  for (let index = 0; index < subAuthorityCount; index++) subAuthorities.push(String(buffer.readUInt32LE(8 + index * 4)));
  return `S-${revision}-${identifierAuthority}${subAuthorities.length ? `-${subAuthorities.join("-")}` : ""}`;
}

export function encodeSid(sid: string): Buffer {
  const parts = sid.split("-");
  if (parts.length < 3 || parts[0] !== "S") throw new Error("value is not a SDDL SID string");
  const revision = Number(parts[1]);
  const identifierAuthority = BigInt(parts[2]);
  const subAuthorities = parts.slice(3).map(Number);
  if (!Number.isInteger(revision) || subAuthorities.some(value => !Number.isInteger(value))) throw new Error("SID string contains a non-numeric component");
  const buffer = Buffer.alloc(8 + subAuthorities.length * 4);
  buffer[0] = revision;
  buffer[1] = subAuthorities.length;
  for (let index = 0; index < 6; index++) buffer[7 - index] = Number((identifierAuthority >> BigInt(8 * index)) & 0xffn);
  subAuthorities.forEach((value, index) => buffer.writeUInt32LE(value >>> 0, 8 + index * 4));
  return buffer;
}

/** The domain SID is every sub-authority except the last (the RID). Undefined when there is no sub-authority to strip. */
export function domainSid(sid: string): string | undefined {
  const parts = sid.split("-");
  return parts.length > 3 ? parts.slice(0, -1).join("-") : undefined;
}
export function sidWithRid(domain: string, rid: number): string { return `${domain}-${rid}`; }
