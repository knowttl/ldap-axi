import { CliError, first, unsupportedFlavorFlag, values, type Directory, type Entry, type Scope, type ServerFlavor } from "./core.js";
import { composeFilter } from "./directory/client.js";
import { filterValue, wildcardValue } from "./directory/escape.js";
import { resolveIdentity, type IdentityQuery } from "./directory/identity.js";
import { decodeSid } from "./directory/sid.js";
import { decodeGuid } from "./directory/guid.js";
import { decodeGeneralizedTime } from "./directory/time.js";
import { decodeGroupType } from "./directory/grouptype.js";
import { memberRowFromEntry, membershipHelp, membershipSummary, readMultivaluedAttribute, resolveDnMembers, type MembershipWalk } from "./directory/membership.js";
import { walkHelp, walkMetadata, walkPages } from "./directory/walk.js";
import { groupListSchema, groupMembersSchema, groupShowSchema, isAdFlavor, selectFields } from "./schema.js";
import { assertAttributes, requestedAttributes } from "./entry.js";
import { compact } from "./render.js";

const MEMBER_COUNT_CAP = 10_000;
function groupIdentityQuery(identifier: string, ad: boolean): IdentityQuery {
  const escaped = filterValue(identifier);
  return ad
    ? { noun: "group", shapeFilter: "(objectCategory=group)", searchFilter: `(&(objectCategory=group)(|(sAMAccountName=${escaped})(cn=${escaped})))` }
    : { noun: "group", shapeFilter: "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))", searchFilter: `(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))(cn=${escaped}))` };
}
/** The membership attribute the entry's own class dictates (docs/design/v1.md \u00a77.2); AD groups always use member. */
function membershipAttribute(entry: Entry, ad: boolean): "member" | "uniqueMember" | "memberUid" {
  if (ad) return "member";
  const classes = values(entry, "objectClass").map(objectClass => objectClass.toLowerCase());
  if (classes.includes("posixgroup")) return "memberUid";
  if (classes.includes("groupofuniquenames")) return "uniqueMember";
  return "member";
}
function groupTypeOf(entry: Entry) { const raw = first(entry, "groupType"); return raw === undefined ? undefined : decodeGroupType(raw); }
function computeGroupField(entry: Entry, name: string, ad: boolean): unknown {
  switch (name) {
    case "dn": return entry.dn;
    case "sam": return first(entry, "sAMAccountName");
    case "name": return first(entry, "cn");
    case "object_class": return values(entry, "objectClass");
    case "member_form": return membershipAttribute(entry, ad) === "memberUid" ? "uid" : undefined;
    case "entry_uuid": return first(entry, "entryUUID");
    case "when_created": { const raw = first(entry, "whenCreated") ?? first(entry, "createTimestamp"); return raw === undefined ? undefined : decodeGeneralizedTime(raw); }
    case "when_changed": { const raw = first(entry, "whenChanged") ?? first(entry, "modifyTimestamp"); return raw === undefined ? undefined : decodeGeneralizedTime(raw); }
    case "object_sid": { const raw = first(entry, "objectSid"); return raw === undefined ? undefined : decodeSid(Buffer.from(raw, "base64")); }
    case "object_guid": { const raw = first(entry, "objectGUID"); return raw === undefined ? undefined : decodeGuid(Buffer.from(raw, "base64")); }
    case "group_type_raw": return groupTypeOf(entry)?.raw;
    case "group_type_unsigned": return groupTypeOf(entry)?.unsigned;
    case "group_scope": return groupTypeOf(entry)?.scope;
    case "security_enabled": return groupTypeOf(entry)?.securityEnabled;
    case "builtin_local": return groupTypeOf(entry)?.builtinLocal;
    case "group_type_flags": return groupTypeOf(entry)?.flags;
    case "group_type_unknown_bits": { const groupType = groupTypeOf(entry); return groupType && groupType.unknownBits !== 0 ? `0x${groupType.unknownBits.toString(16).padStart(8, "0")}` : undefined; }
    case "group_type_valid": return groupTypeOf(entry)?.valid;
    case "group_type_anomalies": { const groupType = groupTypeOf(entry); return groupType && groupType.anomalies.length ? groupType.anomalies : undefined; }
    case "member_count": return undefined; // requires a ranged-retrieval walk; computed by showGroup, not here
    default: return undefined;
  }
}
function renderGroupRow(entry: Entry, names: readonly string[], ad: boolean, attributes?: readonly string[]): Record<string, unknown> {
  const row = { ...compact(Object.fromEntries(names.map(name => [name, computeGroupField(entry, name, ad)]))), ...requestedAttributes(entry, attributes) };
  if (names.includes("object_sid") && row.object_sid !== undefined) row.object_sid_raw = first(entry, "objectSid_raw") ?? first(entry, "objectSid");
  if (names.includes("object_guid") && row.object_guid !== undefined) row.object_guid_raw = first(entry, "objectGUID_raw") ?? first(entry, "objectGUID");
  return row;
}

export type GroupListOptions = Readonly<{
  base: string; flavor: ServerFlavor; pageSize: number; maxRows?: number; limit?: number; all: boolean; scope: Scope;
  name?: string; sam?: string; filter?: string; fields?: readonly string[]; attributes?: readonly string[];
}>;
export async function listGroups(directory: Directory, options: GroupListOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  if (options.sam !== undefined && !ad) throw unsupportedFlavorFlag("sam", options.flavor);
  const schema = groupListSchema(options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(schema, options.fields);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];

  const clauses = [ad ? "(objectCategory=group)" : "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)(objectClass=posixGroup))"];
  if (options.name) clauses.push(`(cn=${wildcardValue(options.name)})`);
  if (options.sam) clauses.push(`(sAMAccountName=${wildcardValue(options.sam)})`);
  if (options.filter) clauses.push(options.filter);
  const filter = composeFilter(clauses);

  const maxRows = options.limit ?? options.maxRows;
  const all = options.all || options.limit !== undefined;
  const walk = await walkPages(directory, { base: options.base, filter, scope: options.scope, attributes, pageSize: options.pageSize }, { maxRows, all });
  if (walk.entries.length === 0 && !walk.stopReason) return { data: { groups: `0 groups matched under ${options.base}`, note: "an entry hidden by access control is indistinguishable from an absent one" }, help: [] };
  return { data: { ...walkMetadata(walk), groups: walk.entries.map(entry => renderGroupRow(entry, names, ad, options.attributes)) }, help: walkHelp(walk) };
}

export type GroupShowOptions = Readonly<{ base: string; flavor: ServerFlavor; identifier: string; pageSize: number; fields?: readonly string[]; attributes?: readonly string[] }>;
export async function showGroup(directory: Directory, options: GroupShowOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  const schema = groupShowSchema(options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(schema, options.fields);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];
  const query = groupIdentityQuery(options.identifier, ad);
  const entry = await resolveIdentity(directory, options.identifier, options.base, query, attributes, options.pageSize);
  const group = renderGroupRow(entry, names, ad, options.attributes);
  if (names.includes("member_count")) {
    const attribute = membershipAttribute(entry, ad);
    const ranged = await readMultivaluedAttribute(directory, entry.dn, attribute, entry, MEMBER_COUNT_CAP);
    group.member_count = ranged.values.length;
    if (!ranged.complete || ad) group.member_count_complete = false;
    if (ranged.stopReason || ad) group.member_count_stop_reason = ranged.stopReason ?? "primary_group_members_not_included";
    if (ad) group.member_count_limitations = ["primary_group_members_not_included"];
    if (ranged.referrals.length) group.referrals = [...new Set(ranged.referrals)].map(uri => ({ uri }));
  }
  return { data: { group }, help: [] };
}

// group members: AD supports --nested via the 1941 matching-rule-in-chain extensible match; a
// generic server has no portable transitive expansion (docs/design/v1.md \u00a76.4, \u00a77.2). Direct
// membership reads member, uniqueMember, or memberUid according to the entry's own class, never
// fabricating DNs for a posixGroup's bare usernames.
export type GroupMembersOptions = Readonly<{ base: string; flavor: ServerFlavor; identifier: string; pageSize: number; maxRows?: number; nested?: boolean; fields?: readonly string[] }>;
function exposePrimaryMembershipLimitation(walk: MembershipWalk, ad: boolean): MembershipWalk {
  return ad && !walk.partial ? { ...walk, partial: true, stopReason: "primary_group_members_not_included" } : walk;
}
export async function groupMembers(directory: Directory, options: GroupMembersOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  if (options.nested && !ad) throw new CliError("UNSUPPORTED_BY_SERVER", "this server does not support transitive group expansion", ["Active Directory supports nested expansion; this server was detected as ldapv3", `Run \`ldap-axi group members ${options.identifier}\` for direct memberships, which will report method and transitive:false`]);
  const schema = groupMembersSchema(options.flavor);
  const { names, attributes, fieldAttributes } = selectFields(schema, options.fields);
  const query = groupIdentityQuery(options.identifier, ad);
  const entry = await resolveIdentity(directory, options.identifier, options.base, query, attributes, options.pageSize);
  const cap = options.maxRows ?? (ad ? 1000 : 500);

  if (options.nested) {
    const filter = composeFilter([`(memberOf:1.2.840.113556.1.4.1941:=${filterValue(entry.dn)})`]);
    const result = await walkPages(directory, { base: options.base, filter, scope: "sub", attributes: fieldAttributes, pageSize: options.pageSize }, { maxRows: cap, all: true });
    const walk = exposePrimaryMembershipLimitation({
      rows: result.entries.map(member => memberRowFromEntry(member, member.dn)), unresolved: [], referrals: result.referrals,
      partial: result.partial || result.incomplete, stopReason: result.stopReason,
    }, ad);
    const rows = walk.rows.map(row => compact(Object.fromEntries(names.map(name => [name, row[name as keyof typeof row]]))));
    return { data: { transitive: true, method: "matching-rule-in-chain", limitations: ["primary_group_members_not_included"], ...membershipSummary(walk, walk.rows.length), members: rows }, help: membershipHelp(walk) };
  }

  const attribute = membershipAttribute(entry, ad);
  const ranged = await readMultivaluedAttribute(directory, entry.dn, attribute, entry, cap);
  let walk: MembershipWalk;
  if (attribute === "memberUid") walk = { rows: ranged.values.map(uid => ({ raw: uid, uid, type: "unresolved" as const })), unresolved: [], referrals: ranged.referrals, partial: !ranged.complete || ranged.referrals.length > 0, stopReason: ranged.stopReason };
  else { const resolved = await resolveDnMembers(directory, ranged.values, cap, fieldAttributes); walk = { ...resolved, referrals: [...resolved.referrals, ...ranged.referrals], partial: resolved.partial || !ranged.complete, stopReason: ranged.stopReason ?? resolved.stopReason }; }

  walk = exposePrimaryMembershipLimitation(walk, ad);
  const rawTotal = walk.rows.length + walk.unresolved.length;
  const rows = walk.rows.map(row => compact(Object.fromEntries(names.map(name => [name, row[name as keyof typeof row]]))));
  return {
    data: { transitive: false, method: attribute, ...(ad ? { limitations: ["primary_group_members_not_included"] } : {}), ...(attribute === "memberUid" ? { member_form: "uid" } : {}), ...membershipSummary(walk, rawTotal), members: rows, ...(walk.unresolved.length ? { unresolved: walk.unresolved } : {}) },
    help: membershipHelp(walk),
  };
}
