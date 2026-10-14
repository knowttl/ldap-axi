import { CliError } from "../core.js";

export type OperationId = "rootDSE" | "searchPaged" | "bind" | "unbind" | "startTLS" | "whoami";
type Effect = "read" | "authentication" | "transport";
type Operation = Readonly<{ id: OperationId; effect: Effect; evidence: Readonly<{ rfc: string; section: string; changes: string }> }>;

function operation(id: OperationId, effect: Effect, rfc: string, section: string, changes: string): Operation {
  return Object.freeze({ id, effect, evidence: Object.freeze({ rfc, section, changes }) });
}
export const OPERATIONS: Readonly<Record<OperationId, Operation>> = Object.freeze({
  rootDSE: operation("rootDSE", "read", "RFC 4512", "5.1", "Reads root DSE"),
  searchPaged: operation("searchPaged", "read", "RFC 4511", "4.5", "Reads entries one page at a time"),
  bind: operation("bind", "authentication", "RFC 4511", "4.2", "Changes connection authorization only"),
  unbind: operation("unbind", "read", "RFC 4511", "4.3", "Closes the connection"),
  startTLS: operation("startTLS", "transport", "RFC 4511", "4.14", "Upgrades transport only"),
  whoami: operation("whoami", "read", "RFC 4532", "1", "Reports current authorization identity")
});
export const EXTENDED_OIDS = Object.freeze(new Set(["1.3.6.1.4.1.1466.20037", "1.3.6.1.4.1.4203.1.11.3"]));
export const CONTROL_OIDS = Object.freeze(new Set(["1.2.840.113556.1.4.319"]));

export function requireOperation(id: OperationId): void { if (!OPERATIONS[id]) throw new CliError("READ_ONLY_VIOLATION", `operation ${id} is not registered`); }
export function requireExtendedOid(oid: string): void { if (!EXTENDED_OIDS.has(oid)) throw new CliError("READ_ONLY_VIOLATION", `extended operation ${oid} is not allowed`); }
