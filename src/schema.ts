import { CliError } from "./core.js";
import type { ServerFlavor } from "./core.js";

// Foundation: one explicit per-command schema owning allowed flags, default output fields,
// selectable fields, the LDAP attributes each field needs, and complete help. Field tables are
// flavor-dependent because AD and generic LDAPv3 genuinely expose different attributes; asking for
// a field the current flavor cannot answer is a VALIDATION_ERROR, never a silently blank column.
export type FieldSpec = Readonly<{ name: string; attributes: readonly string[] }>;
export type CommandSchema = Readonly<{
  summary: string;
  booleanFlags: readonly string[];
  valueFlags: readonly string[];
  fields: readonly FieldSpec[];
  defaultFields: readonly string[];
  requiredAttributes?: readonly string[];
  flagAttributes?: Readonly<Record<string, readonly string[]>>;
}>;
export const isAdFlavor = (flavor: ServerFlavor): boolean => flavor === "ad" || flavor === "adlds";

export function selectFields(schema: CommandSchema, requested: readonly string[] | undefined, enabledFlags: readonly string[] = []): { names: readonly string[]; attributes: readonly string[]; fieldAttributes: readonly string[] } {
  const names = requested ?? schema.defaultFields;
  const known = new Map(schema.fields.map(field => [field.name, field]));
  const unknown = names.filter(name => !known.has(name));
  if (unknown.length) throw new CliError("VALIDATION_ERROR", `unknown field${unknown.length > 1 ? "s" : ""} for --fields: ${unknown.join(", ")}`, [`valid fields: ${schema.fields.map(field => field.name).join(", ")}`]);
  const fieldAttributes = new Set<string>();
  for (const name of names) for (const attribute of known.get(name)!.attributes) fieldAttributes.add(attribute);
  const flagAttributes = enabledFlags.flatMap(flag => schema.flagAttributes?.[flag] ?? []);
  const requestedAttributes = [...new Set([...(schema.requiredAttributes ?? []), ...flagAttributes, ...fieldAttributes])];
  return {
    names,
    fieldAttributes: fieldAttributes.size ? [...fieldAttributes] : ["1.1"],
    attributes: requestedAttributes.length ? requestedAttributes : ["1.1"],
  };
}

export function completeSchema(...schemas: readonly CommandSchema[]): CommandSchema {
  const first = schemas[0];
  const fields = new Map<string, FieldSpec>();
  for (const schema of schemas) for (const field of schema.fields) {
    const existing = fields.get(field.name);
    fields.set(field.name, { name: field.name, attributes: [...new Set([...(existing?.attributes ?? []), ...field.attributes])] });
  }
  return {
    summary: first.summary,
    booleanFlags: [...new Set(schemas.flatMap(schema => schema.booleanFlags))],
    valueFlags: [...new Set(schemas.flatMap(schema => schema.valueFlags))],
    fields: [...fields.values()],
    defaultFields: [...new Set(schemas.flatMap(schema => schema.defaultFields))],
    requiredAttributes: [...new Set(schemas.flatMap(schema => schema.requiredAttributes ?? []))],
    flagAttributes: Object.fromEntries([...new Set(schemas.flatMap(schema => Object.keys(schema.flagAttributes ?? {})))].map(flag => [flag, [...new Set(schemas.flatMap(schema => schema.flagAttributes?.[flag] ?? []))]])),
  };
}

const FLAG_HELP: Readonly<Record<string, string>> = {
  help: "show this help", url: "<ldap[s]://host:port> directory URL", base: "<dn> search base", "start-tls": "upgrade ldap:// using StartTLS",
  "ca-file": "<pem> append a trusted CA", "ca-only": "trust only --ca-file certificates", "tls-no-verify": "disable certificate verification", "tls-max-version": "<1.2> cap verified TLS to TLS 1.2",
  "insecure-plaintext": "allow plaintext LDAP", anonymous: "bind anonymously", profile: "<name> select a saved profile", auth: "<auto|gssapi|simple> authentication selection (default: auto)", "gssapi-service": "<service@fqdn> override the URL-derived GSSAPI service", "gssapi-protection": "<none|confidentiality> required GSSAPI protection; the URL scheme selects it",
  disabled: "include disabled accounts (LDAPv3: permanent ppolicy locks)", enabled: "include enabled accounts (LDAPv3: exclude permanent ppolicy locks)", locked: "include current AD locks or recorded LDAPv3 ppolicy lock candidates",
  all: "read all pages up to --max-rows or --limit", nested: "AD only: expand transitive membership", name: "<pattern> match cn", sam: "<pattern> AD only: match sAMAccountName",
  upn: "<pattern> AD only: match userPrincipalName", uid: "<pattern> LDAPv3 only: match uid", filter: "<RFC4515> add a raw LDAP filter",
  scope: "<base|one|sub> search scope", "max-rows": "<n> maximum output rows", "page-size": "<1..1000> LDAP page size", limit: "<n> alias for bounded list output",
  fields: "<name,...> select output fields", attributes: "<name,...> request and emit raw attributes",
};

export function commandHelp(command: string, ad: CommandSchema, ldapv3: CommandSchema, globalNames: readonly string[]): string {
  const schema = completeSchema(ad, ldapv3);
  const argument = / (?:show|groups|members)$/.test(command) ? " <identifier-or-dn>" : "";
  const flags = [...new Set([...globalNames, ...schema.booleanFlags, ...schema.valueFlags])]
    .map(name => `  --${name}  ${FLAG_HELP[name] ?? ""}`.trimEnd())
    .join("\n");
  const fields = (flavor: string, value: CommandSchema): string => `${flavor} fields: ${value.fields.map(field => field.name).join(", ")}\n${flavor} defaults: ${value.defaultFields.join(", ")}`;
  const exampleArgument = argument.replace("<identifier-or-dn>", "example");
  const userShape = command.startsWith("user ") ? "\nLDAPv3 users are inetOrgPerson or posixAccount entries; use ldap-axi entry search for account + simpleSecurityObject service accounts." : "";
  return `${schema.summary}${userShape}\nUsage: ldap-axi ${command}${argument} [flags]\nFlags:\n${flags}\n${fields("Active Directory", ad)}\n${fields("LDAPv3", ldapv3)}\nExamples:\n  ldap-axi ${command}${exampleArgument} --help\n  ldap-axi ${command}${exampleArgument}`;
}

const IDENTITY_FLAGS = ["max-rows", "page-size", "limit", "fields", "attributes"] as const;

export function userListSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  return {
    summary: "List user accounts.",
    booleanFlags: ["disabled", "enabled", "locked", "all"],
    valueFlags: ["name", "sam", "upn", "uid", "filter", "scope", ...IDENTITY_FLAGS],
    fields: ad
      ? [{ name: "sam", attributes: ["sAMAccountName"] }, { name: "upn", attributes: ["userPrincipalName"] }, { name: "name", attributes: ["cn"] },
        { name: "dn", attributes: [] }, { name: "enabled", attributes: ["userAccountControl"] }, { name: "locked", attributes: ["msDS-User-Account-Control-Computed"] },
        { name: "last_logon", attributes: ["lastLogonTimestamp"] }, { name: "object_sid", attributes: ["objectSid"] }, { name: "when_created", attributes: ["whenCreated"] }]
      : [{ name: "uid", attributes: ["uid"] }, { name: "name", attributes: ["cn"] }, { name: "mail", attributes: ["mail"] },
        { name: "enabled", attributes: ["pwdAccountLockedTime"] }, { name: "locked", attributes: ["pwdAccountLockedTime"] }, { name: "account_state", attributes: ["pwdAccountLockedTime"] },
        { name: "dn", attributes: [] }, { name: "entry_uuid", attributes: ["entryUUID"] }, { name: "when_created", attributes: ["createTimestamp"] }],
    defaultFields: ad ? ["sam", "name", "enabled", "last_logon"] : ["uid", "name", "mail", "enabled", "locked", "account_state"],
    flagAttributes: ad ? { locked: ["msDS-User-Account-Control-Computed"] } : { locked: ["pwdAccountLockedTime"] },
  };
}

export function userShowSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  const fields: FieldSpec[] = ad
    ? [{ name: "dn", attributes: [] }, { name: "sam", attributes: ["sAMAccountName"] }, { name: "upn", attributes: ["userPrincipalName"] }, { name: "name", attributes: ["cn"] },
      { name: "enabled", attributes: ["userAccountControl"] }, { name: "account_state", attributes: ["userAccountControl", "msDS-User-Account-Control-Computed"] },
      { name: "password_last_set", attributes: ["pwdLastSet"] }, { name: "account_expires", attributes: ["accountExpires"] },
      { name: "last_logon", attributes: ["lastLogonTimestamp"] }, { name: "object_sid", attributes: ["objectSid"] }, { name: "object_guid", attributes: ["objectGUID"] },
      { name: "when_created", attributes: ["whenCreated"] }, { name: "when_changed", attributes: ["whenChanged"] }]
    : [{ name: "dn", attributes: [] }, { name: "uid", attributes: ["uid"] }, { name: "name", attributes: ["cn"] }, { name: "mail", attributes: ["mail"] },
      { name: "enabled", attributes: ["pwdAccountLockedTime"] }, { name: "locked", attributes: ["pwdAccountLockedTime"] }, { name: "account_state", attributes: ["pwdAccountLockedTime"] },
      { name: "uid_number", attributes: ["uidNumber"] }, { name: "gid_number", attributes: ["gidNumber"] }, { name: "home_directory", attributes: ["homeDirectory"] },
      { name: "login_shell", attributes: ["loginShell"] }, { name: "gecos", attributes: ["gecos"] }, { name: "entry_uuid", attributes: ["entryUUID"] },
      { name: "when_created", attributes: ["createTimestamp"] }, { name: "when_changed", attributes: ["modifyTimestamp"] }];
  return { summary: "Show one user by DN or identifier.", booleanFlags: [], valueFlags: ["fields", "attributes"], fields, defaultFields: fields.map(field => field.name) };
}

export function userGroupsSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  return {
    summary: "List the groups a user belongs to.",
    booleanFlags: ["nested"],
    valueFlags: ["max-rows", "page-size", "fields"],
    fields: ad
      ? [{ name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] }, { name: "sam", attributes: ["sAMAccountName"] }, { name: "type", attributes: ["objectClass"] }]
      : [{ name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] }, { name: "type", attributes: ["objectClass"] }],
    defaultFields: ["name", "dn", "type"],
    requiredAttributes: ad ? ["tokenGroups", "memberOf", "objectSid", "primaryGroupID"] : ["memberOf", "uid"],
  };
}

export function groupListSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  return {
    summary: "List groups.",
    booleanFlags: ["all"],
    valueFlags: ["name", "sam", "filter", "scope", ...IDENTITY_FLAGS],
    fields: ad
      ? [{ name: "sam", attributes: ["sAMAccountName"] }, { name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] },
        { name: "group_scope", attributes: ["groupType"] }, { name: "security_enabled", attributes: ["groupType"] }]
      : [{ name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] }, { name: "object_class", attributes: ["objectClass"] }],
    defaultFields: ad ? ["sam", "name", "group_scope", "security_enabled"] : ["name", "object_class"],
  };
}

export function groupShowSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  const fields: FieldSpec[] = ad
    ? [{ name: "dn", attributes: [] }, { name: "sam", attributes: ["sAMAccountName"] }, { name: "name", attributes: ["cn"] },
      { name: "group_type_raw", attributes: ["groupType"] }, { name: "group_type_unsigned", attributes: ["groupType"] }, { name: "group_scope", attributes: ["groupType"] },
      { name: "security_enabled", attributes: ["groupType"] }, { name: "builtin_local", attributes: ["groupType"] }, { name: "group_type_flags", attributes: ["groupType"] },
      { name: "group_type_unknown_bits", attributes: ["groupType"] }, { name: "group_type_valid", attributes: ["groupType"] }, { name: "group_type_anomalies", attributes: ["groupType"] },
      { name: "member_count", attributes: ["objectClass", "member"] }, { name: "object_sid", attributes: ["objectSid"] }, { name: "object_guid", attributes: ["objectGUID"] },
      { name: "when_created", attributes: ["whenCreated"] }, { name: "when_changed", attributes: ["whenChanged"] }]
    : [{ name: "dn", attributes: [] }, { name: "name", attributes: ["cn"] }, { name: "object_class", attributes: ["objectClass"] },
      { name: "member_form", attributes: ["objectClass"] }, { name: "member_count", attributes: ["objectClass", "member", "uniqueMember", "memberUid"] },
      { name: "entry_uuid", attributes: ["entryUUID"] }, { name: "when_created", attributes: ["createTimestamp"] }, { name: "when_changed", attributes: ["modifyTimestamp"] }];
  return { summary: "Show one group by DN or identifier.", booleanFlags: [], valueFlags: ["fields", "attributes"], fields, defaultFields: fields.map(field => field.name) };
}

export function groupMembersSchema(flavor: ServerFlavor): CommandSchema {
  const ad = isAdFlavor(flavor);
  return {
    summary: "List a group's members.",
    booleanFlags: ["nested"],
    valueFlags: ["max-rows", "page-size", "fields"],
    fields: ad
      ? [{ name: "sam", attributes: ["sAMAccountName"] }, { name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] }, { name: "type", attributes: ["objectClass"] }]
      : [{ name: "uid", attributes: ["uid"] }, { name: "name", attributes: ["cn"] }, { name: "dn", attributes: [] }, { name: "type", attributes: ["objectClass"] }],
    defaultFields: ad ? ["sam", "name", "type"] : ["uid", "name", "type"],
    requiredAttributes: ad ? ["objectClass", "member"] : ["objectClass", "member", "uniqueMember", "memberUid"],
  };
}
