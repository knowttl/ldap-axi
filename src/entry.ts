import { attributeBaseName, CliError, type Directory, type Entry, type Scope, PASSWORD_ATTRIBUTES } from "./core.js";
import { validateFilter } from "./directory/client.js";
import { walkHelp, walkMetadata, walkPages } from "./directory/walk.js";
import { redactText, truncate } from "./render.js";
import type { SecretRedactor } from "./secrets.js";

export { filterValue, dnValue } from "./directory/escape.js";
export type EntrySearchOptions = Readonly<{ base: string; filter: string; scope: Scope; attributes: readonly string[]; pageSize: number; maxRows?: number; all: boolean; redactor?: SecretRedactor }>;
export const DEFAULT_ENTRY_ATTRIBUTES = ["objectClass", "cn"] as const;
const PASSWORD_ATTRIBUTE_OIDS = new Set(["2.5.4.35", "1.2.840.113556.1.4.90"]);
function isPasswordAttribute(attribute: string): boolean {
  const base = attributeBaseName(attribute).toLowerCase();
  return PASSWORD_ATTRIBUTES.has(base) || PASSWORD_ATTRIBUTE_OIDS.has(base);
}
export function assertAttributes(attributes: readonly string[]): void {
  for (const attribute of attributes) {
    if (attribute === "*" || attribute === "+") throw new CliError("VALIDATION_ERROR", `attribute wildcard ${attribute} is forbidden because it can return password attributes`);
    if (isPasswordAttribute(attribute)) throw new CliError("VALIDATION_ERROR", `attribute ${attribute} is never requested or emitted`);
  }
}
function renderAttribute(name: string, values: readonly string[], redactor?: SecretRedactor): Record<string, unknown> {
  const rendered = values.length === 1 ? truncate(redactText(values[0], redactor)) : values.slice(0, 50).map(value => truncate(redactText(value, redactor)));
  return values.length > 50
    ? { [name]: rendered, [`${name}_value_count`]: values.length, [`${name}_values_truncated`]: true }
    : { [name]: rendered };
}
function renderAttributes(attributes: Entry["attributes"], redactor?: SecretRedactor): Record<string, unknown> {
  return Object.assign({}, ...Object.entries(attributes)
    .filter(([name]) => !isPasswordAttribute(name.replace(/_raw$/, "")))
    .map(([name, values]) => renderAttribute(name, values, redactor)));
}
export function requestedAttributes(entry: Entry, names: readonly string[] | undefined, redactor?: SecretRedactor): Record<string, unknown> {
  if (!names?.length) return {};
  const requested = names.map(name => name.toLowerCase());
  return renderAttributes(Object.fromEntries(Object.entries(entry.attributes)
    .filter(([name]) => {
      const description = name.toLowerCase().replace(/_raw$/, "");
      return requested.some(request => request.includes(";") ? request === description : request === attributeBaseName(description));
    })), redactor);
}
function renderEntry(entry: Entry, redactor?: SecretRedactor): Record<string, unknown> { return { dn: entry.dn, ...renderAttributes(entry.attributes, redactor) }; }
export async function searchEntries(directory: Directory, options: EntrySearchOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  validateFilter(options.filter); assertAttributes(options.attributes);
  const walk = await walkPages(directory, { base: options.base, filter: options.filter, scope: options.scope, attributes: options.attributes, pageSize: options.pageSize }, { maxRows: options.maxRows, all: options.all });
  if (walk.entries.length === 0 && !walk.stopReason) return { data: { entries: `0 entries matched under ${options.base}`, note: "an entry hidden by access control is indistinguishable from an absent one" }, help: [] };
  const data: Record<string, unknown> = { ...walkMetadata(walk), entries: walk.entries.map(entry => renderEntry(entry, options.redactor)) };
  return { data, help: walkHelp(walk) };
}
export async function showEntry(directory: Directory, dn: string, pageSize: number, attributes: readonly string[] = DEFAULT_ENTRY_ATTRIBUTES, redactor?: SecretRedactor): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const result = await searchEntries(directory, { base: dn, filter: "(objectClass=*)", scope: "base", attributes, pageSize, all: true, redactor });
  if (result.data.partial || result.data.incomplete) {
    const reason = String(result.data.stop_reason ?? result.data.incomplete);
    throw new CliError("SERVER_LIMIT", `the directory could not complete the entry read (${reason})`, result.help);
  }
  const entries = result.data.entries;
  if (!Array.isArray(entries) || entries.length === 0) throw new CliError("NOT_FOUND", "no entry matched that distinguished name");
  return { data: { entry: entries[0] }, help: [] };
}
