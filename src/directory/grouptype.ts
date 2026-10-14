// AD groupType: raw + normalized + typed lossless decoding, per the captain-approved
// stage2-identity-grouptype contract. Malformed combinations remain observable data rather than
// becoming a command failure (docs/design/v1.md, MS-ADTS groupType constants).
const BUILTIN_LOCAL_BIT = 0x00000001;
const SCOPE_BITS = [
  { bit: 0x00000002, name: "GLOBAL", scope: "global" },
  { bit: 0x00000004, name: "DOMAIN_LOCAL", scope: "domain_local" },
  { bit: 0x00000008, name: "UNIVERSAL", scope: "universal" },
  { bit: 0x00000010, name: "APPLICATION_BASIC", scope: "application_basic" },
  { bit: 0x00000020, name: "APPLICATION_QUERY", scope: "application_query" },
] as const;
const APPLICATION_BITS = 0x00000030;
const SECURITY_ENABLED_BIT = 0x80000000;
const KNOWN_MASK = 0x8000003f;

export type GroupType = Readonly<{
  raw: number;
  unsigned: number;
  scope: string;
  securityEnabled: boolean;
  builtinLocal: boolean;
  flags: readonly string[];
  unknownBits: number;
  valid: boolean;
  anomalies: readonly string[];
}>;

export function decodeGroupType(value: string): GroupType {
  const raw = Number.parseInt(value, 10);
  const unsigned = raw >>> 0;
  const setScopeBits = SCOPE_BITS.filter(entry => (unsigned & entry.bit) !== 0);
  const builtinLocal = (unsigned & BUILTIN_LOCAL_BIT) !== 0;
  const securityEnabled = (unsigned & SECURITY_ENABLED_BIT) !== 0;
  const unknownBits = unsigned & ~KNOWN_MASK >>> 0;
  const anomalies: string[] = [];
  let scope = "unknown";
  if (setScopeBits.length === 1) scope = setScopeBits[0].scope;
  else if (setScopeBits.length === 0) anomalies.push("no scope or application bit is set");
  else anomalies.push(`multiple scope bits: ${setScopeBits.map(entry => entry.name).join(",")}`);
  if (securityEnabled && (unsigned & APPLICATION_BITS) !== 0) anomalies.push("security-enabled application group is not valid");
  const flags = [...(builtinLocal ? ["BUILTIN_LOCAL"] : []), ...setScopeBits.map(entry => entry.name), ...(securityEnabled ? ["SECURITY_ENABLED"] : [])];
  return {
    raw, unsigned, scope, securityEnabled, builtinLocal, flags,
    unknownBits, valid: unknownBits === 0 && anomalies.length === 0, anomalies,
  };
}
