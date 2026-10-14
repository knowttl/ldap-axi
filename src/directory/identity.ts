import { CliError, type Directory, type Entry, type SearchRequest } from "../core.js";
import { isDn } from "./dn.js";

// The accepted stage2-identity-grouptype contract: a syntactically valid DN gets one base-scope
// read with required object-shape validation and no fallback; a non-DN identifier gets one exact
// escaped flavor-specific search. Zero matches is NOT_FOUND, one is returned, and two or more is
// VALIDATION_ERROR requiring a DN. Never a preferred match, a retry, or a selector flag.
// Cardinality is counted over the entries the searched server actually returned; continuation
// references are reported in the NOT_FOUND help, never chased and never counted.
export type IdentityQuery = Readonly<{
  noun: string;
  shapeFilter: string;
  searchFilter: string;
}>;

const AMBIGUITY_CAP = 5;
type IdentityResult = Readonly<{ entries: readonly Entry[]; referrals: readonly string[]; incomplete?: string }>;
// A `SearchResultReference` does not make the searched naming context incomplete: the server
// answered in full for the base it holds and named the subtrees it does not hold. An AD domain-root
// search always carries these for the configuration and DNS partitions, so treating one as an
// incomplete search made every identifier lookup at a domain root fail (docs/design/v1.md §5.5).
// A terminal result code 10 is different - nothing was searched - and arrives as a stopReason.
async function collect(directory: Directory, request: SearchRequest, cap: number): Promise<IdentityResult> {
  const entries: Entry[] = [];
  const referrals: string[] = [];
  let incomplete: string | undefined;
  for await (const page of directory.searchPages(request)) {
    for (const entry of page.entries) { entries.push(entry); if (entries.length >= cap) break; }
    if (page.referrals?.length) referrals.push(...page.referrals);
    if (page.stopReason) incomplete = page.stopReason;
    if (entries.length >= cap || incomplete) break;
  }
  return { entries, referrals: [...new Set(referrals)], incomplete };
}
function requireComplete(result: IdentityResult, noun: string): IdentityResult {
  if (result.incomplete) throw new CliError("SERVER_LIMIT", `the directory could not establish a unique ${noun} because the search was incomplete (${result.incomplete})`, ["Narrow the search base or use a distinguished name"]);
  return result;
}
// Referrals are reported, never chased (§9.6), so an absent identifier names the subtrees that were
// not searched instead of implying the directory has no such entry anywhere.
function notFoundHelp(referrals: readonly string[]): string[] {
  const help = [`Run the command again with a distinguished name if you have one`];
  if (referrals.length) help.push(`These subtrees were referred and not searched: ${referrals.join(", ")}`, "Run the same search with `--url` pointing at the referred server to include its results");
  return help;
}

export async function resolveIdentity(directory: Directory, identifier: string, base: string, query: IdentityQuery, attributes: readonly string[], pageSize: number): Promise<Entry> {
  if (isDn(identifier)) {
    const { entries } = requireComplete(await collect(directory, { base: identifier, filter: query.shapeFilter, scope: "base", attributes, pageSize }, 1), query.noun);
    if (entries.length === 0) throw new CliError("NOT_FOUND", `no ${query.noun} matched that distinguished name`, [`The DN must resolve and satisfy the ${query.noun} shape (${query.shapeFilter})`]);
    return entries[0];
  }
  const { entries, referrals } = requireComplete(await collect(directory, { base, filter: query.searchFilter, scope: "sub", attributes, pageSize }, AMBIGUITY_CAP), query.noun);
  if (entries.length === 0) throw new CliError("NOT_FOUND", `no ${query.noun} matched "${identifier}"`, notFoundHelp(referrals));
  if (entries.length > 1) throw new CliError("VALIDATION_ERROR", `"${identifier}" matches more than one ${query.noun}`, [`Pass the distinguished name of the specific ${query.noun} you mean`]);
  return entries[0];
}
