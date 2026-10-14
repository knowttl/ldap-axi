// userAccountControl bitfield decoding (docs/design/v1.md §6.1). The same decoder also reads
// msDS-User-Account-Control-Computed, which is where LOCKOUT and PASSWORD_EXPIRED must be sourced
// from on Windows Server 2003 and later domains; the raw bitfield's copies of those two bits are
// reported for transparency but never used to derive locked_out or password_expired.
const UAC_FLAGS = [
  { name: "SCRIPT", bit: 0x0001 },
  { name: "ACCOUNTDISABLE", bit: 0x0002 },
  { name: "HOMEDIR_REQUIRED", bit: 0x0008 },
  { name: "LOCKOUT", bit: 0x0010 },
  { name: "PASSWD_NOTREQD", bit: 0x0020 },
  { name: "PASSWD_CANT_CHANGE", bit: 0x0040 },
  { name: "ENCRYPTED_TEXT_PWD_ALLOWED", bit: 0x0080 },
  { name: "TEMP_DUPLICATE_ACCOUNT", bit: 0x0100 },
  { name: "NORMAL_ACCOUNT", bit: 0x0200 },
  { name: "INTERDOMAIN_TRUST_ACCOUNT", bit: 0x0800 },
  { name: "WORKSTATION_TRUST_ACCOUNT", bit: 0x1000 },
  { name: "SERVER_TRUST_ACCOUNT", bit: 0x2000 },
  { name: "DONT_EXPIRE_PASSWORD", bit: 0x10000 },
  { name: "MNS_LOGON_ACCOUNT", bit: 0x20000 },
  { name: "SMARTCARD_REQUIRED", bit: 0x40000 },
  { name: "TRUSTED_FOR_DELEGATION", bit: 0x80000 },
  { name: "NOT_DELEGATED", bit: 0x100000 },
  { name: "USE_DES_KEY_ONLY", bit: 0x200000 },
  { name: "DONT_REQ_PREAUTH", bit: 0x400000 },
  { name: "PASSWORD_EXPIRED", bit: 0x800000 },
  { name: "TRUSTED_TO_AUTH_FOR_DELEGATION", bit: 0x1000000 },
  { name: "PARTIAL_SECRETS_ACCOUNT", bit: 0x04000000 },
] as const;

export type Uac = Readonly<{ raw: number; flags: readonly string[] }>;
export function decodeUserAccountControl(value: string): Uac {
  const raw = Number.parseInt(value, 10);
  return { raw, flags: UAC_FLAGS.filter(flag => (raw & flag.bit) !== 0).map(flag => flag.name) };
}
export const UAC_LOCKOUT_BIT = 0x0010;
export const UAC_PASSWORD_EXPIRED_BIT = 0x800000;
export const UAC_ACCOUNTDISABLE_BIT = 0x0002;
