export type ErrorCode =
  | "VALIDATION_ERROR" | "CREDENTIAL_INCOMPLETE" | "AUTH_REQUIRED" | "AUTH_FAILED"
  | "ACCOUNT_DISABLED" | "ACCOUNT_LOCKED" | "ACCOUNT_EXPIRED" | "PASSWORD_EXPIRED"
  | "INSUFFICIENT_ACCESS" | "STRONGER_AUTH_REQUIRED" | "INVALID_DN" | "UNSUPPORTED_BY_SERVER" | "SERVER_BUSY"
  | "NOT_FOUND" | "TLS_REQUIRED" | "TLS_UNTRUSTED" | "SERVER_UNREACHABLE"
  | "GSSAPI_UNAVAILABLE" | "GSSAPI_CREDENTIAL_UNAVAILABLE" | "GSSAPI_PREPARATION_FAILED" | "GSSAPI_NEGOTIATION_FAILED"
  | "OPERATION_TIMEOUT" | "CURSOR_EXPIRED" | "SERVER_LIMIT" | "READ_ONLY_VIOLATION"
  | "PROTOCOL_ERROR" | "UNKNOWN";

export class CliError extends Error {
  constructor(readonly code: ErrorCode, message: string, readonly help: string[] = [], readonly exitCode = code === "VALIDATION_ERROR" || code === "CREDENTIAL_INCOMPLETE" ? 2 : 1) {
    super(message);
    if (code === "NOT_FOUND") this.help = [...help, "The search base may be absent or hidden by access control; if using --anonymous, try an authenticated bind with read access"];
  }
}

export type Scope = "base" | "one" | "sub";
export type AttributeMap = Readonly<Record<string, readonly string[]>>;
export type SearchRequest = Readonly<{ base: string; filter: string; scope: Scope; attributes: readonly string[]; pageSize: number }>;
export type SearchPage = Readonly<{ entries: readonly Entry[]; cookie?: string; referrals?: readonly string[]; stopReason?: "server_size_limit" | "server_admin_limit" | "server_time_limit" | "referral" }>;
export type Entry = Readonly<{ dn: string; attributes: AttributeMap }>;
export type ServerFlavor = "ad" | "adlds" | "ldapv3";
export type RootDse = Readonly<{ attributes: AttributeMap; flavor: ServerFlavor }>;

export interface Directory {
  readonly flavor: ServerFlavor;
  rootDSE(): Promise<RootDse>;
  searchPages(request: SearchRequest): AsyncIterable<SearchPage>;
  whoami(): Promise<string | undefined>;
  close(): Promise<void>;
}

export const ROOT_DSE_ATTRIBUTES = ["supportedCapabilities", "supportedControl", "supportedExtension", "supportedLDAPVersion", "supportedSASLMechanisms", "namingContexts", "vendorName", "vendorVersion", "subschemaSubentry", "defaultNamingContext"] as const;
export const PASSWORD_ATTRIBUTES = new Set(["userpassword", "unicodepwd"]);
export function attributeBaseName(description: string): string { return description.split(";", 1)[0]; }

export function values(entry: Entry, name: string): readonly string[] { return entry.attributes[name.toLowerCase()] ?? entry.attributes[name] ?? []; }
export function first(entry: Entry, name: string): string | undefined { return values(entry, name)[0]; }
/** A recognized flag that the current server's flavor cannot honor (docs/design/v1.md §12.2, §7.2). */
export function unsupportedFlavorFlag(flag: string, flavor: ServerFlavor): CliError {
  return new CliError("UNSUPPORTED_BY_SERVER", `--${flag} is not supported on a ${flavor} server`, ["This flag requires Active Directory or AD LDS"]);
}
