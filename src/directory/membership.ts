import { CliError, first, values, type Directory, type Entry, type SearchRequest } from "../core.js";
import { decodeEntryAttribute } from "./attributes.js";
import { composeFilter } from "./client.js";
import { binaryFilterValue } from "./escape.js";
import { decodeSid, encodeSid } from "./sid.js";

// The membership result model (foundation 3): composing a row budget, referrals, AD ranged-value
// retrieval, and honest totals across membership sources (DN lists, SID lists, bare
// usernames). Source selection and composition are per-command decisions made by user.ts/group.ts; this
// module supplies the mechanical primitives shared by both.
export type MemberRow = Readonly<{ raw: string; dn?: string; name?: string; sam?: string; uid?: string; type: "user" | "group" | "other" | "unresolved" }>;
export type Unresolved = Readonly<{ raw: string; reason: string }>;
export type MembershipWalk = Readonly<{ rows: readonly MemberRow[]; unresolved: readonly Unresolved[]; referrals: readonly string[]; partial: boolean; stopReason?: string }>;

const RESOLUTION_ATTRIBUTES = ["cn", "sAMAccountName", "uid", "objectClass"] as const;

type FirstPage = Readonly<{ entries: readonly Entry[]; referrals: readonly string[]; stopReason?: string }>;
async function firstPage(directory: Directory, request: SearchRequest): Promise<FirstPage> {
  for await (const page of directory.searchPages(request)) return { entries: page.entries, referrals: page.referrals ?? [], stopReason: page.stopReason };
  return { entries: [], referrals: [] };
}
function classify(entry: Entry): MemberRow["type"] {
  const classes = values(entry, "objectClass");
  if (classes.some(objectClass => /group/i.test(objectClass))) return "group";
  if (classes.some(objectClass => /person|account|^user$/i.test(objectClass))) return "user";
  return "other";
}
export function memberRowFromEntry(entry: Entry, raw: string): MemberRow {
  return { raw, dn: entry.dn, name: first(entry, "cn"), sam: first(entry, "sAMAccountName"), uid: first(entry, "uid"), type: classify(entry) };
}
/** uniqueMember carries an optional "#<bitstring>" UID suffix (RFC 4512 NameAndOptionalUID). */
export function stripOptionalUid(raw: string): string {
  const match = /^(.*)#'[01]*'B$/.exec(raw);
  return match ? match[1] : raw;
}
function isVisibilityGap(error: unknown): boolean {
  return error instanceof CliError && (error.code === "NOT_FOUND" || error.code === "INSUFFICIENT_ACCESS");
}

/** Resolves DN-form member references (member, uniqueMember, memberOf) via one base-scope read each, up to cap. */
export async function resolveDnMembers(directory: Directory, dns: readonly string[], cap: number, attributes: readonly string[] = RESOLUTION_ATTRIBUTES): Promise<MembershipWalk> {
  const bounded = dns.slice(0, cap);
  const rows: MemberRow[] = []; const unresolved: Unresolved[] = []; const referrals: string[] = []; let stopReason: string | undefined;
  for (const raw of bounded) {
    const dn = stripOptionalUid(raw);
    try {
      const page = await firstPage(directory, { base: dn, filter: "(objectClass=*)", scope: "base", attributes, pageSize: 1 });
      referrals.push(...page.referrals);
      stopReason ??= page.stopReason;
      if (page.entries.length === 0) unresolved.push({ raw, reason: page.stopReason ? `resolution incomplete (${page.stopReason})` : "not found or not readable with the current bind" });
      else rows.push(memberRowFromEntry(page.entries[0], raw));
    } catch (error) {
      if (isVisibilityGap(error)) unresolved.push({ raw, reason: "not found or not readable with the current bind" });
      else throw error;
    }
  }
  return { rows, unresolved, referrals, partial: dns.length > cap || referrals.length > 0 || stopReason !== undefined, stopReason };
}

/** Resolves AD tokenGroups SIDs to names via one batched objectSid OR-filter search per chunk. */
export async function resolveSidMembers(directory: Directory, base: string, sids: readonly string[], cap: number, pageSize: number, attributes: readonly string[] = RESOLUTION_ATTRIBUTES): Promise<MembershipWalk> {
  const bounded = sids.slice(0, cap);
  const referrals: string[] = [];
  const found = new Map<string, Entry>();
  let stopReason: string | undefined;
  const CHUNK_SIZE = 50;
  for (let offset = 0; offset < bounded.length; offset += CHUNK_SIZE) {
    const chunk = bounded.slice(offset, offset + CHUNK_SIZE);
    const clauses = chunk.map(sid => `(objectSid=${binaryFilterValue(encodeSid(sid))})`);
    const filter = composeFilter([`(|${clauses.join("")})`]);
    for await (const page of directory.searchPages({ base, filter, scope: "sub", attributes: [...new Set([...attributes, "objectSid"])], pageSize: Math.min(pageSize, chunk.length) })) {
      referrals.push(...(page.referrals ?? []));
      for (const entry of page.entries) {
        const sid = decodeEntryAttribute(entry, "objectSid", raw => decodeSid(Buffer.from(raw, "base64")));
        if (sid !== undefined) found.set(sid, entry);
      }
      if (page.stopReason) { stopReason ??= page.stopReason; break; }
    }
  }
  const rows: MemberRow[] = []; const unresolved: Unresolved[] = [];
  for (const sid of bounded) {
    const entry = found.get(sid);
    if (entry) rows.push(memberRowFromEntry(entry, sid));
    else unresolved.push({ raw: sid, reason: stopReason ? `resolution incomplete (${stopReason})` : "not found under the resolved base (commonly a cross-domain or foreign security principal)" });
  }
  return { rows, unresolved, referrals, partial: sids.length > cap || referrals.length > 0 || stopReason !== undefined, stopReason };
}

const RANGE_KEY = /^(.+);range=(\d+|\*)-(\d+|\*)$/i;
function rangedKeyFor(entry: Entry, attribute: string): { key: string; upper: string } | undefined {
  const pattern = new RegExp(`^${attribute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")};range=(\\d+|\\*)-(\\d+|\\*)$`, "i");
  const key = Object.keys(entry.attributes).find(candidate => pattern.test(candidate));
  if (!key) return undefined;
  const match = RANGE_KEY.exec(key);
  return match ? { key, upper: match[3] } : undefined;
}
/**
 * Reads a multi-valued attribute in full, following AD's ranged-retrieval continuation
 * (attributeName;range=start-end) until the server reports the final chunk (end is "*") or the
 * row cap is reached. An attribute the server never ranged is returned as-is.
 */
export async function readMultivaluedAttribute(directory: Directory, dn: string, attribute: string, entry: Entry, cap: number): Promise<{ values: readonly string[]; complete: boolean; referrals: readonly string[]; stopReason?: string }> {
  const ranged = rangedKeyFor(entry, attribute);
  if (!ranged) {
    const all = values(entry, attribute);
    return { values: all.slice(0, cap), complete: all.length <= cap, referrals: [] };
  }
  let collected = [...entry.attributes[ranged.key]];
  let upper = ranged.upper;
  const referrals: string[] = [];
  let stopReason: string | undefined;
  while (upper !== "*" && collected.length < cap) {
    const next = Number(upper) + 1;
    const page = await firstPage(directory, { base: dn, filter: "(objectClass=*)", scope: "base", attributes: [`${attribute};range=${next}-*`], pageSize: 1 });
    referrals.push(...page.referrals);
    stopReason ??= page.stopReason;
    const nextRanged = page.entries[0] ? rangedKeyFor(page.entries[0], attribute) : undefined;
    if (!nextRanged) break;
    collected = collected.concat(page.entries[0].attributes[nextRanged.key]);
    upper = nextRanged.upper;
  }
  return { values: collected.slice(0, cap), complete: upper === "*" && collected.length <= cap && referrals.length === 0 && stopReason === undefined, referrals, stopReason };
}

/** The honest count/partial/stop-reason/referrals fragment shared by user groups and group members. */
export function membershipSummary(walk: MembershipWalk, rawTotal: number): Record<string, unknown> {
  const resolvedCount = walk.rows.length + walk.unresolved.length;
  const partial = walk.partial || resolvedCount < rawTotal;
  return {
    count: `${resolvedCount} of ${partial ? "unknown" : resolvedCount} total`,
    ...(partial ? { partial: true, stop_reason: walk.stopReason ?? (walk.referrals.length ? "referral" : "max_rows") } : {}),
    ...(walk.referrals.length ? { referrals: [...new Set(walk.referrals)].map(uri => ({ uri })) } : {}),
  };
}

export function membershipHelp(walk: MembershipWalk): string[] {
  if (!walk.partial) return [];
  const reason = walk.stopReason ?? (walk.referrals.length ? "referral" : "max_rows");
  if (reason === "primary_group_unavailable") return ["The directory did not expose or resolve objectSid and primaryGroupID needed to expand the primary group"];
  if (reason === "primary_group_members_not_included") return ["Active Directory does not expose primaryGroupID membership through member or memberOf; these members are not included"];
  if (reason === "referral") return ["Referrals are reported but not chased; query the referred directory directly"];
  if (reason === "unique_member_uid_not_checked") return ["uniqueMember values with an optional UID suffix cannot be ruled out by a DN-only reverse search; these memberships may be missing"];
  if (reason.startsWith("server_")) return ["Narrow the search base or membership scope to stay within the directory server limit"];
  return ["Re-run with a higher --max-rows for a more complete bounded read"];
}
