import { CliError, first, unsupportedFlavorFlag, values, type Directory, type Entry, type Scope, type ServerFlavor } from "./core.js";
import { decodeAttribute, decodeEntryAttribute } from "./directory/attributes.js";
import { composeFilter } from "./directory/client.js";
import { filterValue, wildcardValue } from "./directory/escape.js";
import { resolveIdentity, type IdentityQuery } from "./directory/identity.js";
import { isDn } from "./directory/dn.js";
import { decodeSid, domainSid, sidWithRid } from "./directory/sid.js";
import { decodeGuid } from "./directory/guid.js";
import { decodeFiletime, decodeGeneralizedTime } from "./directory/time.js";
import { decodeUserAccountControl, UAC_ACCOUNTDISABLE_BIT, UAC_LOCKOUT_BIT, UAC_PASSWORD_EXPIRED_BIT } from "./directory/uac.js";
import { membershipHelp, membershipSummary, readMultivaluedAttribute, resolveDnMembers, resolveSidMembers, type MembershipWalk } from "./directory/membership.js";
import { walkHelp, walkMetadata, walkPages } from "./directory/walk.js";
import { isAdFlavor, selectFields, userGroupsSchema, userListSchema, userShowSchema } from "./schema.js";
import { assertAttributes, renderAttribute, requestedAttributes } from "./entry.js";
import { compact } from "./render.js";
import type { SecretRedactor } from "./secrets.js";

const PERMANENT_PASSWORD_LOCK = "000001010000Z";

function isPermanentPasswordLock(time: string | undefined): boolean {
  return time !== undefined && decodeAttribute("pwdAccountLockedTime", () => decodeGeneralizedTime(time)) === decodeGeneralizedTime(PERMANENT_PASSWORD_LOCK);
}

function userIdentityQuery(identifier: string, ad: boolean): IdentityQuery {
  const escaped = filterValue(identifier);
  return ad
    ? { noun: "user", shapeFilter: "(objectCategory=person)", searchFilter: `(&(objectCategory=person)(|(sAMAccountName=${escaped})(userPrincipalName=${escaped})))` }
    : { noun: "user", shapeFilter: "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))", searchFilter: `(&(|(objectClass=inetOrgPerson)(objectClass=posixAccount))(uid=${escaped}))` };
}

function accountState(entry: Entry): Record<string, unknown> | undefined {
  const uacRaw = first(entry, "userAccountControl");
  if (uacRaw === undefined) {
    const time = first(entry, "pwdAccountLockedTime");
    if (time === undefined) return undefined;
    // Ordinary timestamps can survive an expired lock. The effective policy may be
    // an unreadable server default, so presence alone never proves a current lock.
    return isPermanentPasswordLock(time)
      ? { enabled: false, locked_out: true, pwd_account_locked_time: time }
      : { pwd_account_locked_time: time, locked_out: "unknown" };
  }
  const uac = decodeUserAccountControl(uacRaw);
  const computedRaw = first(entry, "msDS-User-Account-Control-Computed");
  const computed = computedRaw !== undefined ? decodeUserAccountControl(computedRaw) : undefined;
  return compact({
    enabled: (uac.raw & UAC_ACCOUNTDISABLE_BIT) === 0,
    locked_out: computed ? (computed.raw & UAC_LOCKOUT_BIT) !== 0 : undefined,
    password_expired: computed ? (computed.raw & UAC_PASSWORD_EXPIRED_BIT) !== 0 : undefined,
    user_account_control_raw: uac.raw,
    user_account_control_flags: uac.flags,
  });
}
function computeUserField(entry: Entry, name: string): unknown {
  switch (name) {
    case "dn": return entry.dn;
    case "sam": return first(entry, "sAMAccountName");
    case "upn": return first(entry, "userPrincipalName");
    case "name": return first(entry, "cn");
    case "uid": return first(entry, "uid");
    case "mail": return first(entry, "mail");
    case "uid_number": return first(entry, "uidNumber");
    case "gid_number": return first(entry, "gidNumber");
    case "home_directory": return first(entry, "homeDirectory");
    case "login_shell": return first(entry, "loginShell");
    case "gecos": return first(entry, "gecos");
    case "entry_uuid": return first(entry, "entryUUID");
    case "when_created": return decodeEntryAttribute(entry, ["whenCreated", "createTimestamp"], decodeGeneralizedTime);
    case "when_changed": return decodeEntryAttribute(entry, ["whenChanged", "modifyTimestamp"], decodeGeneralizedTime);
    case "object_sid": return decodeEntryAttribute(entry, "objectSid", raw => decodeSid(Buffer.from(raw, "base64")));
    case "object_guid": return decodeEntryAttribute(entry, "objectGUID", raw => decodeGuid(Buffer.from(raw, "base64")));
    case "enabled": { const raw = first(entry, "userAccountControl"); return raw === undefined ? accountState(entry)?.enabled : (decodeUserAccountControl(raw).raw & UAC_ACCOUNTDISABLE_BIT) === 0; }
    case "locked": { const raw = first(entry, "msDS-User-Account-Control-Computed"); return raw === undefined ? (accountState(entry)?.locked_out === true ? true : undefined) : (decodeUserAccountControl(raw).raw & UAC_LOCKOUT_BIT) !== 0; }
    case "last_logon": return decodeEntryAttribute(entry, "lastLogonTimestamp", decodeFiletime);
    case "password_last_set": return decodeEntryAttribute(entry, "pwdLastSet", decodeFiletime);
    case "account_expires": return decodeEntryAttribute(entry, "accountExpires", decodeFiletime);
    case "account_state": return accountState(entry);
    default: return undefined;
  }
}
function renderUserRow(entry: Entry, names: readonly string[], attributes?: readonly string[], redactor?: SecretRedactor): Record<string, unknown> {
  const row = { ...compact(Object.fromEntries(names.map(name => [name, computeUserField(entry, name)]))), ...requestedAttributes(entry, attributes, redactor) };
  for (const [name, attribute] of [["description", "description"], ["display_name", "displayName"], ["memberOf", "memberOf"]]) {
    if (!names.includes(name)) continue;
    for (const [key, fieldValues] of Object.entries(entry.attributes)) {
      const match = /^([^;]+)(;range=\d+-(?:\d+|\*))?$/i.exec(key);
      if (match && match[1].toLowerCase() === attribute.toLowerCase() && fieldValues.length) Object.assign(row, renderAttribute(match[2] ? key : name, fieldValues, redactor, name === "memberOf"));
    }
  }
  if (names.includes("object_sid") && row.object_sid !== undefined) row.object_sid_raw = first(entry, "objectSid_raw") ?? first(entry, "objectSid");
  if (names.includes("object_guid") && row.object_guid !== undefined) row.object_guid_raw = first(entry, "objectGUID_raw") ?? first(entry, "objectGUID");
  return row;
}

export type UserListOptions = Readonly<{
  base: string; flavor: ServerFlavor; pageSize: number; maxRows?: number; limit?: number; all: boolean; scope: Scope;
  name?: string; sam?: string; upn?: string; uid?: string; disabled?: boolean; enabled?: boolean; locked?: boolean;
  filter?: string; fields?: readonly string[]; attributes?: readonly string[]; redactor?: SecretRedactor;
}>;

async function requirePasswordPolicySchema(directory: Directory, flag: string, base: string, pageSize: number): Promise<void> {
  const root = await directory.rootDSE();
  let schemaDn = first({ dn: "", attributes: root.attributes }, "subschemaSubentry");
  if (!schemaDn) {
    for await (const page of directory.searchPages({ base, scope: "base", filter: "(objectClass=*)", attributes: ["subschemaSubentry"], pageSize })) {
      schemaDn = page.entries[0] && first(page.entries[0], "subschemaSubentry");
    }
  }
  if (schemaDn) {
    for await (const page of directory.searchPages({ base: schemaDn, scope: "base", filter: "(objectClass=*)", attributes: ["attributeTypes"], pageSize })) {
      if (page.entries.some(entry => values(entry, "attributeTypes").some(definition => /\bNAME\s+(?:'pwdAccountLockedTime'|\([^)]*'pwdAccountLockedTime')/i.test(definition)))) return;
    }
  }
  throw new CliError("UNSUPPORTED_BY_SERVER", `--${flag} requires a readable pwdAccountLockedTime schema on LDAPv3`, ["Grant read access to subschemaSubentry and its attributeTypes, or use a directory with the password-policy schema"]);
}

export async function listUsers(directory: Directory, options: UserListOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  if (options.sam !== undefined && !ad) throw unsupportedFlavorFlag("sam", options.flavor);
  if (options.upn !== undefined && !ad) throw unsupportedFlavorFlag("upn", options.flavor);
  if (options.uid !== undefined && ad) throw unsupportedFlavorFlag("uid", options.flavor);
  const stateFlag = options.disabled ? "disabled" : options.enabled ? "enabled" : options.locked ? "locked" : undefined;
  if (stateFlag && !ad) await requirePasswordPolicySchema(directory, stateFlag, options.base, options.pageSize);
  const schema = userListSchema(options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(schema, options.fields, options.locked ? ["locked"] : []);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];

  const clauses = [ad ? "(objectCategory=person)" : "(|(objectClass=inetOrgPerson)(objectClass=posixAccount))"];
  if (options.name) clauses.push(`(cn=${wildcardValue(options.name)})`);
  if (options.sam) clauses.push(`(sAMAccountName=${wildcardValue(options.sam)})`);
  if (options.upn) clauses.push(`(userPrincipalName=${wildcardValue(options.upn)})`);
  if (options.uid) clauses.push(`(uid=${wildcardValue(options.uid)})`);
  if (options.disabled) clauses.push(ad ? "(userAccountControl:1.2.840.113556.1.4.803:=2)" : `(pwdAccountLockedTime=${PERMANENT_PASSWORD_LOCK})`);
  if (options.enabled) clauses.push(ad ? "(!(userAccountControl:1.2.840.113556.1.4.803:=2))" : `(!(pwdAccountLockedTime=${PERMANENT_PASSWORD_LOCK}))`);
  if (options.locked) clauses.push(ad ? "(lockoutTime>=1)" : "(pwdAccountLockedTime=*)");
  if (options.filter) clauses.push(options.filter);
  const filter = composeFilter(clauses);

  const maxRows = options.limit ?? options.maxRows;
  const all = options.all || options.limit !== undefined;
  const include = options.locked && ad
    ? (entry: Entry): boolean => {
      const computed = first(entry, "msDS-User-Account-Control-Computed");
      return computed !== undefined && (decodeUserAccountControl(computed).raw & UAC_LOCKOUT_BIT) !== 0;
    }
    : undefined;
  const walk = await walkPages(directory, { base: options.base, filter, scope: options.scope, attributes, pageSize: options.pageSize }, { maxRows, all, include });
  const stateHelp = !ad && stateFlag ? ["LDAPv3 filters inspect readable pwdAccountLockedTime: --disabled selects permanent administrative locks; --enabled excludes those locks and does not prove authentication is allowed; --locked selects recorded lock candidates"] : [];
  const uncertain = !ad && options.locked && walk.entries.some(entry => !isPermanentPasswordLock(first(entry, "pwdAccountLockedTime")));
  if (uncertain) stateHelp.push("Timed locks may have expired: the effective pwdLockoutDuration policy is unavailable, so candidates without locked:true have unknown current state");
  if (walk.entries.length === 0 && !walk.stopReason) return { data: { users: `0 users matched under ${options.base}`, note: "an entry hidden by access control is indistinguishable from an absent one" }, help: stateHelp };
  return { data: { ...walkMetadata(walk), ...(uncertain ? { partial: true, account_state_incomplete: "lockout_policy_unavailable" } : {}), users: walk.entries.map(entry => renderUserRow(entry, names, options.attributes, options.redactor)) }, help: [...walkHelp(walk), ...stateHelp] };
}

export type UserShowOptions = Readonly<{ base: string; flavor: ServerFlavor; identifier: string; pageSize: number; fields?: readonly string[]; attributes?: readonly string[]; redactor?: SecretRedactor }>;
export async function showUser(directory: Directory, options: UserShowOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  const schema = userShowSchema(options.flavor);
  const { names, attributes: fieldAttributes } = selectFields(schema, options.fields);
  if (options.attributes?.length) assertAttributes(options.attributes);
  const attributes = [...new Set([...fieldAttributes, ...(options.attributes ?? [])])];
  const query = userIdentityQuery(options.identifier, ad);
  const entry = await resolveIdentity(directory, options.identifier, options.base, query, attributes, options.pageSize);
  const user = renderUserRow(entry, names, options.attributes, options.redactor);
  if (names.includes("last_logon") && "last_logon" in user) user.last_logon_precision = "approximate";
  return { data: { user }, help: [] };
}

// user groups: tokenGroups (transitive, includes the primary group) is the AD default; a server
// that returns no tokenGroups falls back to memberOf plus an explicit primaryGroupID resolution,
// which is not transitive (docs/design/v1.md \u00a76.4). Generic LDAPv3 prefers memberOf, falling back
// to a reverse search, and --nested has no portable meaning off Active Directory (\u00a77.2).
export type UserGroupsOptions = Readonly<{ base: string; flavor: ServerFlavor; identifier: string; pageSize: number; maxRows?: number; nested?: boolean; fields?: readonly string[] }>;

function combineMembership(primary: MembershipWalk, secondary: MembershipWalk): MembershipWalk {
  const rows = [...primary.rows, ...secondary.rows];
  return {
    rows: rows.filter((row, index) => rows.findIndex(candidate => (candidate.dn ?? candidate.raw).toLowerCase() === (row.dn ?? row.raw).toLowerCase()) === index),
    unresolved: [...primary.unresolved, ...secondary.unresolved],
    referrals: [...new Set([...primary.referrals, ...secondary.referrals])],
    partial: primary.partial || secondary.partial,
    stopReason: primary.stopReason ?? secondary.stopReason,
  };
}

async function primaryGroup(directory: Directory, base: string, entry: Entry, pageSize: number, rowAttributes: readonly string[]): Promise<MembershipWalk> {
  const sid = first(entry, "objectSid");
  const primaryGroupId = first(entry, "primaryGroupID");
  if (sid && primaryGroupId) {
    const domain = domainSid(decodeAttribute("objectSid", () => decodeSid(Buffer.from(sid, "base64"))));
    if (domain) return resolveSidMembers(directory, base, [sidWithRid(domain, Number(primaryGroupId))], 1, pageSize, rowAttributes);
  }
  return { rows: [], unresolved: [], referrals: [], partial: true, stopReason: "primary_group_unavailable" };
}

async function adUserGroups(directory: Directory, base: string, entry: Entry, cap: number, pageSize: number, rowAttributes: readonly string[], nested: boolean): Promise<{ walk: MembershipWalk; method: string; transitive: boolean }> {
  const tokenGroupSids = values(entry, "tokenGroups").map(base64 => decodeAttribute("tokenGroups", () => decodeSid(Buffer.from(base64, "base64"))));
  if (tokenGroupSids.length > 0) return { walk: await resolveSidMembers(directory, base, tokenGroupSids, cap, pageSize, rowAttributes), method: "tokenGroups", transitive: true };
  const primary = await primaryGroup(directory, base, entry, pageSize, rowAttributes);
  const primaryCount = primary.rows.length + primary.unresolved.length;
  const remaining = Math.max(0, cap - primaryCount);
  if (nested) {
    if (remaining === 0) {
      const chain: MembershipWalk = { rows: [], unresolved: [], referrals: [], partial: true, stopReason: "max_rows" };
      return { walk: combineMembership(primary, chain), method: "matching-rule-in-chain+primaryGroupID", transitive: true };
    }
    const chainSources = [entry.dn, primary.rows[0]?.dn].filter((dn): dn is string => dn !== undefined);
    const chainClauses = chainSources.map(dn => `(member:1.2.840.113556.1.4.1941:=${filterValue(dn)})`);
    const chainFilter = chainClauses.length === 1 ? chainClauses[0] : `(|${chainClauses.join("")})`;
    const filter = composeFilter(["(objectCategory=group)", chainFilter, ...(primary.rows[0]?.dn ? [`(!(distinguishedName=${filterValue(primary.rows[0].dn)}))`] : [])]);
    const result = await walkPages(directory, { base, filter, scope: "sub", attributes: rowAttributes, pageSize }, { maxRows: remaining, all: true });
    const primaryGroupResolved = primary.rows[0]?.dn !== undefined;
    const chain: MembershipWalk = {
      rows: result.entries.map(group => ({ raw: group.dn, dn: group.dn, name: first(group, "cn"), sam: first(group, "sAMAccountName"), type: "group" })),
      unresolved: [], referrals: result.referrals,
      partial: result.partial || result.incomplete || !primaryGroupResolved,
      stopReason: result.stopReason ?? (primaryGroupResolved ? undefined : "primary_group_unavailable"),
    };
    return { walk: combineMembership(primary, chain), method: "matching-rule-in-chain+primaryGroupID", transitive: true };
  }
  const ranged = await readMultivaluedAttribute(directory, entry.dn, "memberOf", entry, remaining);
  const resolved = await resolveDnMembers(directory, ranged.values, remaining, rowAttributes);
  const memberOf: MembershipWalk = {
    ...resolved,
    referrals: [...resolved.referrals, ...ranged.referrals],
    partial: resolved.partial || !ranged.complete,
    stopReason: ranged.stopReason ?? resolved.stopReason,
  };
  return { walk: combineMembership(primary, memberOf), method: "memberOf+primaryGroupID", transitive: false };
}
async function genericUserGroups(directory: Directory, base: string, entry: Entry, cap: number, pageSize: number, rowAttributes: readonly string[]): Promise<{ walk: MembershipWalk; method: string; transitive: boolean }> {
  const memberOfDns = values(entry, "memberOf");
  const memberOf = await resolveDnMembers(directory, memberOfDns, cap, rowAttributes);
  const known = new Set([...memberOf.rows.map(row => row.dn!.toLowerCase()), ...memberOf.unresolved.map(row => row.raw.toLowerCase())]);
  const remaining = Math.max(0, cap - memberOf.rows.length - memberOf.unresolved.length);
  const uid = first(entry, "uid");
  const dnGroups = `(&(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames))(|(member=${filterValue(entry.dn)})(uniqueMember=${filterValue(entry.dn)})))`;
  const posixGroups = uid ? `(&(objectClass=posixGroup)(memberUid=${filterValue(uid)}))` : "";
  const filter = composeFilter([`(|${dnGroups}${posixGroups})`]);
  const walk = await walkPages(directory, { base, filter, scope: "sub", attributes: rowAttributes, pageSize }, { maxRows: remaining, all: true, include: group => !known.has(group.dn.toLowerCase()) });
  const combined = combineMembership(memberOf, { rows: walk.entries.map(group => ({ raw: group.dn, dn: group.dn, name: first(group, "cn"), type: "group" as const })), unresolved: [], referrals: walk.referrals, partial: walk.partial || walk.incomplete, stopReason: walk.stopReason });
  // uniqueMemberMatch includes the optional UID in equality. A DN-only assertion cannot
  // rule out memberships carrying that suffix, even when the reverse search is exhausted.
  return { walk: { ...combined, partial: true, stopReason: combined.stopReason ?? (combined.referrals.length ? "referral" : combined.partial ? "max_rows" : "unique_member_uid_not_checked") }, method: memberOfDns.length ? "memberOf+reverse-search" : "reverse-search", transitive: false };
}

export async function userGroups(directory: Directory, options: UserGroupsOptions): Promise<{ data: Record<string, unknown>; help: string[] }> {
  const ad = isAdFlavor(options.flavor);
  if (options.nested && !ad) throw new CliError("UNSUPPORTED_BY_SERVER", "this server does not support transitive group expansion", ["Active Directory supports nested expansion; this server was detected as ldapv3", `Run \`ldap-axi user groups ${options.identifier}\` for direct memberships, which will report method and transitive:false`]);
  const schema = userGroupsSchema(options.flavor);
  const { names, attributes, fieldAttributes } = selectFields(schema, options.fields);
  const query = userIdentityQuery(options.identifier, ad);
  const needsBaseRead = ad && !isDn(options.identifier);
  const resolved = await resolveIdentity(directory, options.identifier, options.base, query, needsBaseRead ? attributes.filter(attribute => attribute !== "tokenGroups") : attributes, options.pageSize);
  const entry = needsBaseRead ? await resolveIdentity(directory, resolved.dn, options.base, query, attributes, options.pageSize) : resolved;
  const cap = options.maxRows ?? (ad ? 1000 : 500);
  const { walk, method, transitive } = ad ? await adUserGroups(directory, options.base, entry, cap, options.pageSize, fieldAttributes, Boolean(options.nested)) : await genericUserGroups(directory, options.base, entry, cap, options.pageSize, fieldAttributes);
  const rawTotal = walk.rows.length + walk.unresolved.length;
  const rows = walk.rows.map(row => compact(Object.fromEntries(names.map(name => [name, row[name as keyof typeof row]]))));
  return {
    data: { transitive, method, ...membershipSummary(walk, rawTotal), groups: rows, ...(walk.unresolved.length ? { unresolved: walk.unresolved } : {}) },
    help: membershipHelp(walk),
  };
}
