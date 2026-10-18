import { first, unsupportedFlavorFlag, type Directory, type Entry, type Scope, type ServerFlavor } from "./core.js";
import { composeFilter } from "./directory/client.js";
import { filterValue, wildcardValue } from "./directory/escape.js";
import { resolveIdentity } from "./directory/identity.js";
import { decodeSid } from "./directory/sid.js";
import { decodeGuid } from "./directory/guid.js";
import { decodeFiletime, decodeGeneralizedTime } from "./directory/time.js";
import { decodeUserAccountControl } from "./directory/uac.js";
import { walkHelp, walkMetadata, walkPages } from "./directory/walk.js";
import { computerListSchema, computerShowSchema, isAdFlavor, selectFields } from "./schema.js";
import { assertAttributes, requestedAttributes } from "./entry.js";
import { compact, redactText, truncate } from "./render.js";
import type { SecretRedactor } from "./secrets.js";

const GENERIC_SHAPE = "(objectClass=device)";
function computerShape(ad: boolean): string { return ad ? "(objectCategory=computer)" : GENERIC_SHAPE; }
function computeField(entry: Entry, name: string, ad: boolean): unknown {
  switch (name) {
    case "dn": return entry.dn;
    case "enabled": { const raw = first(entry, "userAccountControl"); return raw === undefined ? undefined : (decodeUserAccountControl(raw).raw & 2) === 0; }
    case "last_logon": { const raw = first(entry, "lastLogonTimestamp"); return raw === undefined ? undefined : decodeFiletime(raw); }
    case "object_sid": { const raw = first(entry, "objectSid"); return raw === undefined ? undefined : decodeSid(Buffer.from(raw, "base64")); }
    case "object_guid": { const raw = first(entry, "objectGUID"); return raw === undefined ? undefined : decodeGuid(Buffer.from(raw, "base64")); }
    case "when_created": { const raw = first(entry, ad ? "whenCreated" : "createTimestamp"); return raw === undefined ? undefined : decodeGeneralizedTime(raw); }
    case "when_changed": { const raw = first(entry, ad ? "whenChanged" : "modifyTimestamp"); return raw === undefined ? undefined : decodeGeneralizedTime(raw); }
    default: {
      const attribute = { sam: "sAMAccountName", name: "cn", dns_host_name: "dNSHostName", operating_system: "operatingSystem", operating_system_version: "operatingSystemVersion", description: "description", entry_uuid: "entryUUID" }[name];
      return attribute ? first(entry, attribute) : undefined;
    }
  }
}
function computerRow(entry: Entry, names: readonly string[], ad: boolean, attributes?: readonly string[], redactor?: SecretRedactor): Record<string, unknown> {
  const row = compact(Object.fromEntries(names.map(name => { const value = computeField(entry, name, ad); return [name, typeof value === "string" ? truncate(redactText(value, redactor)) : value]; })));
  if (names.includes("object_sid") && row.object_sid !== undefined) row.object_sid_raw = first(entry, "objectSid_raw") ?? first(entry, "objectSid");
  if (names.includes("object_guid") && row.object_guid !== undefined) row.object_guid_raw = first(entry, "objectGUID_raw") ?? first(entry, "objectGUID");
  if (names.includes("last_logon") && row.last_logon !== undefined) row.last_logon_precision = "approximate";
  return { ...row, ...requestedAttributes(entry, attributes, redactor) };
}

export type ComputerListOptions = Readonly<{
  base: string; flavor: ServerFlavor; pageSize: number; maxRows?: number; limit?: number; all: boolean; scope: Scope;
  name?: string; sam?: string; filter?: string; fields?: readonly string[]; attributes?: readonly string[]; redactor?: SecretRedactor;
}>;
export async function listComputers(directory: Directory, options: ComputerListOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  if (options.sam !== undefined && !ad) throw unsupportedFlavorFlag("sam", options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(computerListSchema(options.flavor), options.fields);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];
  const clauses = [computerShape(ad)];
  if (options.name) clauses.push(`(cn=${wildcardValue(options.name)})`);
  if (options.sam) clauses.push(`(sAMAccountName=${wildcardValue(options.sam)})`);
  if (options.filter) clauses.push(options.filter);
  const walk = await walkPages(directory, { base: options.base, filter: composeFilter(clauses), scope: options.scope, attributes, pageSize: options.pageSize }, { maxRows: options.limit ?? options.maxRows, all: options.all || options.limit !== undefined });
  const fallback = ad ? {} : { fallback_filter: GENERIC_SHAPE };
  if (walk.entries.length === 0 && !walk.stopReason) return {
    data: { ...fallback, computers: ad ? `0 computers matched under ${options.base}` : `0 entries matched the generic fallback filter "${GENERIC_SHAPE}" under ${options.base}`, note: "an entry hidden by access control is indistinguishable from an absent one" },
    help: ad ? [] : ["This server was not detected as Active Directory; computer used a generic device fallback, and machine accounts may not exist in this directory", 'Run `ldap-axi entry search --filter "(objectClass=*)" --scope one` to explore object classes under the selected base'],
  };
  return { data: { ...fallback, ...walkMetadata(walk), computers: walk.entries.map(entry => computerRow(entry, names, ad, options.attributes, options.redactor)) }, help: [...walkHelp(walk), "Run `ldap-axi computer show <identifier-or-dn>` for computer details"] };
}

export type ComputerShowOptions = Readonly<{ base: string; flavor: ServerFlavor; identifier: string; pageSize: number; fields?: readonly string[]; attributes?: readonly string[]; redactor?: SecretRedactor }>;
export async function showComputer(directory: Directory, options: ComputerShowOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(computerShowSchema(options.flavor), options.fields);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];
  const escaped = filterValue(options.identifier);
  const shapeFilter = computerShape(ad);
  const searchFilter = `(&${shapeFilter}${ad ? `(|(sAMAccountName=${escaped})(cn=${escaped}))` : `(cn=${escaped})`})`;
  const entry = await resolveIdentity(directory, options.identifier, options.base, { noun: ad ? "computer" : "computer using the generic fallback (objectClass=device)", shapeFilter, searchFilter }, attributes, options.pageSize);
  return { data: { ...(ad ? {} : { fallback_filter: GENERIC_SHAPE }), computer: computerRow(entry, names, ad, options.attributes, options.redactor) }, help: [] };
}
