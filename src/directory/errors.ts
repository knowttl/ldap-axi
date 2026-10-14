import { CliError, type ErrorCode } from "../core.js";
import { trace } from "./trace.js";

export function noAmbientCredential(platformName: NodeJS.Platform = process.platform): CliError {
  const action = platformName === "win32" ? "Sign in with a domain account" : "Obtain an ambient credential with kinit or the platform's normal sign-in";
  return new CliError("GSSAPI_CREDENTIAL_UNAVAILABLE", "no usable ambient Kerberos/SSPI credential", [action, "Use --auth simple in a new invocation with a complete simple-bind credential"]);
}

// The single translation boundary for every LDAP result code and connection-level failure,
// shared by rootDSE, bind, and every search (docs/design/v1.md §12). Result codes 3, 4, and 11
// reaching here mean "no entries were retained": a page walk that retains entries handles those
// codes itself, before an error ever reaches this function (§9.5, client.ts searchPages).
function resultCode(error: unknown): number | undefined {
  const code = (error as { code?: unknown }).code;
  return typeof code === "number" ? code : undefined;
}
function diagnosticMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

// AD bind sub-error codes (docs/design/v1.md §6.6), reproduced from Broadcom KB 51487 and
// LDAPWiki: high-confidence operational fact, not a primary Microsoft specification table.
const AD_BIND_SUB_CODES: Readonly<Record<string, Readonly<{ code: ErrorCode; meaning: string }>>> = {
  "525": { code: "AUTH_FAILED", meaning: "user not found" },
  "52e": { code: "AUTH_FAILED", meaning: "valid user, wrong password" },
  "52f": { code: "AUTH_FAILED", meaning: "account restriction (for example, blank password not allowed)" },
  "530": { code: "AUTH_FAILED", meaning: "not permitted to log on at this time" },
  "531": { code: "AUTH_FAILED", meaning: "not permitted to log on at this workstation" },
  "532": { code: "PASSWORD_EXPIRED", meaning: "password expired" },
  "533": { code: "ACCOUNT_DISABLED", meaning: "account disabled" },
  "568": { code: "AUTH_FAILED", meaning: "too many context ids" },
  "701": { code: "ACCOUNT_EXPIRED", meaning: "account expired" },
  "773": { code: "PASSWORD_EXPIRED", meaning: "must reset password at next logon" },
  "775": { code: "ACCOUNT_LOCKED", meaning: "account locked out" },
};
export function adBindSubCode(message: string): string | undefined { return /data ([0-9a-fA-F]+)/.exec(message)?.[1]?.toLowerCase(); }

function translateBindFailure(message: string): CliError {
  const subCode = adBindSubCode(message);
  const entry = subCode ? AD_BIND_SUB_CODES[subCode] : undefined;
  if (entry) return new CliError(entry.code, `directory authentication failed: ${entry.meaning}`, ["ldap-axi cannot resolve this; an administrator must (docs/design/v1.md §1.5)"]);
  return new CliError("AUTH_FAILED", subCode ? `directory authentication failed (unrecognized sub-code ${subCode})` : "directory authentication failed", ["Verify the bind DN form: Active Directory accepts user@domain or a full DN"]);
}

const NARROW_HELP = ["Narrow the filter, lower --max-rows, or scope the base more tightly"];
function translateResultCode(code: number): CliError {
  switch (code) {
    case 2: return new CliError("PROTOCOL_ERROR", "the server reported a protocol error");
    case 3: return new CliError("SERVER_LIMIT", "the server's time limit stopped the operation before any entries were retained", NARROW_HELP);
    case 4: return new CliError("SERVER_LIMIT", "the server's size limit stopped the operation before any entries were retained", NARROW_HELP);
    case 8: case 13: return new CliError("STRONGER_AUTH_REQUIRED", "the server requires a stronger or encrypted bind", ["Use ldaps:// or --start-tls"]);
    case 11: return new CliError("SERVER_LIMIT", "an administrative limit stopped the operation before any entries were retained", NARROW_HELP);
    case 12: return new CliError("UNSUPPORTED_BY_SERVER", "the server does not support the requested control or extension");
    case 32: return new CliError("NOT_FOUND", "no entry matched that request");
    case 34: return new CliError("INVALID_DN", "the server rejected the distinguished name as malformed");
    case 50: return new CliError("INSUFFICIENT_ACCESS", "the bound identity is not permitted to read this", ["Read access to this subtree is required"]);
    case 51: case 52: return new CliError("SERVER_BUSY", "the server is busy or unavailable");
    default: return new CliError("UNKNOWN", `unrecognized LDAP result code ${code}`);
  }
}

function translateConnectionError(message: string): CliError {
  if (/GSSAPI protected LDAP transport failed|LDAP SASL transport|GSSAPI negotiation/i.test(message)) {
    trace("gssapi-negotiation-failure", () => ({ phase: "ldap-error-translation" }));
    return new CliError("GSSAPI_NEGOTIATION_FAILED", "GSSAPI protected LDAP transport failed", ["The selected SASL mechanism did not complete its bounded RFC 4752 exchange; no fallback occurred"]);
  }
  if (/certificate|self.signed|unable_to_verify|unable_to_get_issuer/i.test(message)) return new CliError("TLS_UNTRUSTED", "certificate verification failed", ["Use --ca-file <pem> to append a corporate CA, or NODE_EXTRA_CA_CERTS; Node does not use the system trust store"]);
  if (/timed out|timeout|etimedout/i.test(message)) return new CliError("OPERATION_TIMEOUT", "the operation deadline elapsed");
  if (/econnrefused|enotfound|eai_again|enetunreach|ehostunreach/i.test(message)) return new CliError("SERVER_UNREACHABLE", "could not connect to the directory");
  return new CliError("UNKNOWN", "an unexpected directory error occurred");
}

/** Translates any thrown ldapts error, or a connection-level failure, into the §12.2 code table. */
export function translateLdapError(error: unknown): CliError {
  if (error instanceof CliError) return error;
  const message = diagnosticMessage(error);
  const code = resultCode(error);
  if (code === 49) return translateBindFailure(message);
  if (code !== undefined) return translateResultCode(code);
  return translateConnectionError(message);
}
